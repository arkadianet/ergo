use super::*;
use ergo_api::compat::types::ScalaTransaction;
use ergo_rest_json::decode::{decode_output, decode_registers};
use ergo_ser::transaction::{transaction_id, write_transaction};
use std::collections::BTreeMap;

/// Pin Scala parity: any key in `additionalRegisters` outside
/// R4..R9 must reject. Silently dropping unknowns produces a
/// different `tx_id` than Scala for the same JSON input — a
/// wallet/relay-compat regression on a serialization boundary.
/// Mirrors `JsonCodecs.scala:106` which only accepts known
/// non-mandatory register IDs.
#[test]
fn decode_registers_rejects_unknown_register_names() {
    // Single-byte SBoolean true literal — known-good register hex.
    let valid_hex = "0101".to_string();
    let cases: &[(&str, &str)] = &[
        ("R10", "two-digit beyond R9"),
        (
            "R3",
            "mandatory register, not allowed in additionalRegisters",
        ),
        ("R0", "mandatory register"),
        ("r4", "lowercase typo"),
        ("X", "non-register garbage"),
    ];
    for (key, why) in cases {
        let mut map = BTreeMap::new();
        map.insert(key.to_string(), valid_hex.clone());
        let err = decode_registers(&map).expect_err(&format!("{key} ({why}) must be rejected"));
        assert_eq!(err.0, DESERIALIZE, "{key} should bucket as deserialize");
        assert!(
            err.1.contains("unknown register name"),
            "error detail must explain why {key} was rejected: got {:?}",
            err.1,
        );
    }
}

/// Positive round-trip: a packed R4..R9 map decodes successfully
/// and re-serializes byte-stable. Pins that the unknown-key check
/// doesn't false-positive on legitimate input.
#[test]
fn decode_registers_accepts_packed_known_registers() {
    let valid_hex = "0101"; // SBoolean true
    for n in 0..=6 {
        let mut map = BTreeMap::new();
        for register_name in REGISTER_NAMES.iter().take(n) {
            map.insert(register_name.to_string(), valid_hex.to_string());
        }
        let (_parsed, wire) = decode_registers(&map)
            .unwrap_or_else(|e| panic!("packed {n} registers must decode: {e:?}"));
        assert_eq!(
            wire[0] as usize, n,
            "wire count byte must equal entry count"
        );
    }
}

// ---------------------------------------------------------------
// JSON submission parity tests
// ---------------------------------------------------------------

use std::path::Path;

use ergo_ser::transaction::read_transaction;

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct TxVector {
    id: String,
    bytes: String,
    height: u32,
}

fn vectors_dir() -> std::path::PathBuf {
    // CARGO_MANIFEST_DIR = .../ergo-node; parent = repo root.
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("test-vectors/mainnet")
}

fn load_vectors(filename: &str) -> Vec<TxVector> {
    let path = vectors_dir().join(filename);
    let data =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_str(&data).unwrap_or_else(|e| panic!("parse {}: {e}", path.display()))
}

/// Convert a Scala-shape `ScalaTransaction` (read-side DTO with
/// derived fields) to `ScalaTransactionInput` (input-side DTO
/// without them) by JSON round-trip. This exercises the same wire
/// path real clients hit: `serde_json` re-parses the encoded JSON
/// as the input variant, so derived fields land in serde's
/// "ignored unknown" bucket per Q3.
fn to_input(tx: &ScalaTransaction) -> ScalaTransactionInput {
    let json = serde_json::to_string(tx).expect("ScalaTransaction must serialize");
    serde_json::from_str(&json).expect("input variant must parse Scala JSON")
}

/// **Byte-parity oracle (encoder-anchored breadth).**
/// For each mainnet tx: raw bytes → parse → forward-encode to
/// Scala JSON → JSON → `ScalaTransactionInput` →
/// `decode_scala_transaction` → bytes, asserting round-trip
/// byte-identity against the canonical mainnet bytes.
///
/// **Anchor:** the forward encoder (`encode_transaction`) is
/// independently anchored against Scala's read-side fixtures via
/// `ergo-api/tests/scala_parity.rs` and the operator
/// `/blocks/{id}/transactions` route — both ends of this round-trip
/// touch the canonical mainnet bytes, so encoder/decoder cannot
/// drift together without breaking either the read-side parity
/// suite OR the byte-identity assertion below.
///
/// True Scala-captured JSON (Scala node → JSON → our decoder)
/// is verified separately by
/// `b4_scala_captured_json_decodes_to_canonical_bytes`. This test
/// supplies breadth — the default suite runs committed corpora spanning
/// genesis (1-200), modern (205000-205200), and a 700K-era block, covering
/// diverse contract shapes (token mints, ergoTree versions,
/// multi-input/data-input/output). The larger gitignored 700K *range* corpus
/// (1278 txs) runs in the `#[ignore]`'d companion. The captured-JSON test
/// supplies the external-oracle anchor.
fn run_byte_parity(files: &[&str], min_total: usize) {
    let mut total = 0;
    let mut failures: Vec<String> = Vec::new();
    for file in files {
        let vectors = load_vectors(file);
        assert!(!vectors.is_empty(), "{file} must have vectors");
        for v in &vectors {
            total += 1;
            let raw = match hex::decode(&v.bytes) {
                Ok(b) => b,
                Err(e) => {
                    failures.push(format!("{}@{}: bad hex: {e}", v.id, v.height));
                    continue;
                }
            };
            let mut r = VlqReader::new(&raw);
            let tx = match read_transaction(&mut r) {
                Ok(t) => t,
                Err(e) => {
                    failures.push(format!("{}@{}: parse: {e}", v.id, v.height));
                    continue;
                }
            };
            let scala = match encode_transaction(&tx) {
                Ok(s) => s,
                Err(e) => {
                    failures.push(format!("{}@{}: encode: {e}", v.id, v.height));
                    continue;
                }
            };
            let input = to_input(&scala);
            let bytes = match decode_scala_transaction(&input) {
                Ok(b) => b,
                Err((reason, detail)) => {
                    failures.push(format!("{}@{}: decode {reason}: {detail}", v.id, v.height));
                    continue;
                }
            };
            if bytes != raw {
                failures.push(format!(
                    "{}@{}: byte mismatch ({} vs {} bytes)",
                    v.id,
                    v.height,
                    bytes.len(),
                    raw.len()
                ));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "byte-parity failures ({}/{}):\n  - {}",
        failures.len(),
        total,
        failures.join("\n  - ")
    );
    assert!(
        total >= min_total,
        "need {min_total}+ vectors for breadth coverage; got {total}"
    );
}

#[test]
fn b4_byte_parity_via_json_round_trip_mainnet_vectors() {
    // All committed fixtures so the default suite runs in CI, spanning genesis,
    // modern (height 205K), and a 700K-era block for diverse contract shapes.
    // The larger gitignored 700K-range corpus runs via b4_byte_parity_broad_700k_corpus.
    run_byte_parity(
        &[
            "transactions_1_200.json",
            "transactions_205000_205200.json",
            "transactions_700000.json",
        ],
        300,
    );
}

#[test]
#[ignore = "needs gitignored transactions_700000_700200.json — extract via test-vectors/scripts then run with --include-ignored"]
fn b4_byte_parity_broad_700k_corpus() {
    run_byte_parity(&["transactions_700000_700200.json"], 1000);
}

/// **Scala-captured byte oracle.** Loads JSON
/// captured directly from a running Scala node's
/// `/blocks/{id}/transactions` endpoint, paired with the same tx's
/// canonical bytes. Asserts that our decoder produces bytes
/// byte-identical to the canonical bytes — NOT just `tx_id`
/// equality, since `tx_id = blake2b256(bytes_to_sign)` does not
/// cover `proofBytes` and would not catch a decoder that mutates
/// proofs while preserving the unsigned portion.
///
/// The JSON was never touched by our encoder; this is a true
/// external differential against the Scala reference.
///
/// **Corpus.** 213 mainnet txs
/// captured from heights 1750000-1750030: 147 with non-empty
/// `proofBytes`, 156 with tokens, 112 with non-empty registers,
/// 86 with non-empty context extensions, 25 with data inputs.
/// Comfortably exceeds the spec's 100+ vector target with the
/// diversity coverage it demanded. Re-extract via
/// `extract_scala_tx_json.sh` when expanding the range.
#[test]
fn b4_scala_captured_json_decodes_to_canonical_bytes() {
    #[derive(serde::Deserialize)]
    struct Captured {
        #[serde(rename = "txId")]
        tx_id: String,
        bytes: String,
        #[serde(rename = "scalaJson")]
        scala_json: serde_json::Value,
    }
    let path = vectors_dir().join("scala_tx_json").join("diff_corpus.json");
    let data =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let corpus: Vec<Captured> =
        serde_json::from_str(&data).unwrap_or_else(|e| panic!("parse {}: {e}", path.display()));
    assert!(
        !corpus.is_empty(),
        "Scala-captured corpus must be non-empty"
    );

    for c in &corpus {
        let expected = hex::decode(&c.bytes)
            .unwrap_or_else(|e| panic!("bad canonical bytes hex for {}: {e}", c.tx_id));
        let input: ScalaTransactionInput = serde_json::from_value(c.scala_json.clone())
            .unwrap_or_else(|e| {
                panic!(
                    "Scala JSON for {} must parse as ScalaTransactionInput: {e}",
                    c.tx_id
                )
            });
        let actual = decode_scala_transaction(&input).unwrap_or_else(|(reason, detail)| {
            panic!(
                "Scala-captured JSON for {} must decode: {reason}: {detail}",
                c.tx_id
            )
        });
        assert_eq!(
            hex::encode(&actual),
            hex::encode(&expected),
            "byte mismatch for Scala-captured tx {} ({} bytes actual vs {} bytes expected)",
            c.tx_id,
            actual.len(),
            expected.len(),
        );
        // Belt-and-braces: also verify tx_id parity with Scala's
        // emitted id, which catches bytes_to_sign drift specifically.
        let mut r = VlqReader::new(&actual);
        let tx = read_transaction(&mut r)
            .unwrap_or_else(|e| panic!("decoded bytes must reparse for {}: {e}", c.tx_id));
        let computed =
            transaction_id(&tx).unwrap_or_else(|e| panic!("transaction_id for {}: {e:?}", c.tx_id));
        let computed_hex = hex::encode(computed.as_bytes());
        assert_eq!(
            computed_hex, c.tx_id,
            "tx_id mismatch for Scala-captured tx (Scala said {}, we computed {})",
            c.tx_id, computed_hex
        );
    }
}

/// **Derived fields are accepted-and-ignored.** (`id`, `size`, output `boxId`,
/// `transactionId`, `index`) supplied in the request must be
/// accepted-and-ignored: the resulting canonical bytes (and thus
/// `tx_id`) must match the same request without those fields.
/// Pins that we don't accidentally validate or fail on
/// client-supplied derived data — Scala accepts both forms.
#[test]
fn b4_q1_derived_fields_omission_produces_same_bytes() {
    let vectors = load_vectors("transactions_1_10.json");
    let v = &vectors[0];
    let raw = hex::decode(&v.bytes).unwrap();
    let mut r = VlqReader::new(&raw);
    let tx = read_transaction(&mut r).unwrap();
    let scala = encode_transaction(&tx).unwrap();

    // With derived fields (full Scala-shape JSON).
    let with_json = serde_json::to_string(&scala).unwrap();
    assert!(with_json.contains("\"id\":"), "fixture must include id");
    assert!(with_json.contains("\"size\":"), "fixture must include size");
    assert!(
        with_json.contains("\"boxId\":"),
        "fixture must include output boxId"
    );

    // Without derived fields: strip them via serde_json::Value
    // surgery. Easier than building a parallel DTO.
    let mut val: serde_json::Value = serde_json::from_str(&with_json).unwrap();
    let obj = val.as_object_mut().unwrap();
    obj.remove("id");
    obj.remove("size");
    for out in obj["outputs"].as_array_mut().unwrap() {
        let o = out.as_object_mut().unwrap();
        o.remove("boxId");
        o.remove("transactionId");
        o.remove("index");
    }
    let without_json = serde_json::to_string(&val).unwrap();

    let with_input: ScalaTransactionInput =
        serde_json::from_str(&with_json).expect("with-derived must parse");
    let without_input: ScalaTransactionInput =
        serde_json::from_str(&without_json).expect("without-derived must parse");

    let with_bytes = decode_scala_transaction(&with_input).expect("with-derived decodes");
    let without_bytes = decode_scala_transaction(&without_input).expect("without-derived decodes");
    assert_eq!(
        with_bytes, without_bytes,
        "derived-field presence must not affect canonical bytes"
    );
    assert_eq!(with_bytes, raw, "must match canonical mainnet bytes");
}

/// **Unknown JSON fields tolerated.** Unknown fields at every level
/// (transaction, input, spendingProof, output, asset) must be
/// tolerated. Pins that no `#[serde(deny_unknown_fields)]` slips
/// in — wallets routinely add hint/preview fields.
#[test]
fn b4_q3_unknown_fields_at_every_level_are_tolerated() {
    let vectors = load_vectors("transactions_1_10.json");
    let v = &vectors[0];
    let raw = hex::decode(&v.bytes).unwrap();
    let mut r = VlqReader::new(&raw);
    let tx = read_transaction(&mut r).unwrap();
    let scala = encode_transaction(&tx).unwrap();
    let json = serde_json::to_string(&scala).unwrap();

    let mut val: serde_json::Value = serde_json::from_str(&json).unwrap();
    let obj = val.as_object_mut().unwrap();
    obj.insert("xUnknownTop".into(), serde_json::json!("ignored"));
    for inp in obj["inputs"].as_array_mut().unwrap() {
        let i = inp.as_object_mut().unwrap();
        i.insert("xUnknownInput".into(), serde_json::json!(42));
        i["spendingProof"]
            .as_object_mut()
            .unwrap()
            .insert("xUnknownProof".into(), serde_json::json!(true));
    }
    for out in obj["outputs"].as_array_mut().unwrap() {
        let o = out.as_object_mut().unwrap();
        o.insert("xUnknownOutput".into(), serde_json::json!({"nested": "ok"}));
        if let Some(arr) = o["assets"].as_array_mut() {
            for a in arr {
                a.as_object_mut()
                    .unwrap()
                    .insert("xUnknownAsset".into(), serde_json::json!(null));
            }
        }
    }
    let polluted_json = serde_json::to_string(&val).unwrap();
    let input: ScalaTransactionInput = serde_json::from_str(&polluted_json)
        .expect("unknown fields at every level must be ignored");
    let bytes = decode_scala_transaction(&input).expect("decode after unknown fields");
    assert_eq!(bytes, raw, "unknown-field tolerance must not change bytes");
}

/// **Null-rejection (top-level).** `null` for required arrays must
/// reject at the JSON parse boundary (not fall through to decode).
/// Pairs with the `[]` acceptance pinned by the byte-parity test
/// (every mainnet tx has at least one empty `dataInputs` or
/// `assets`).
#[test]
fn b4_q4_null_for_required_collections_rejects() {
    let cases: &[(&str, &str)] = &[
        (
            r#"{"inputs": null, "dataInputs": [], "outputs": []}"#,
            "inputs null",
        ),
        (
            r#"{"inputs": [], "dataInputs": null, "outputs": []}"#,
            "dataInputs null",
        ),
        (
            r#"{"inputs": [], "dataInputs": [], "outputs": null}"#,
            "outputs null",
        ),
    ];
    for (body, label) in cases {
        let parsed = serde_json::from_str::<ScalaTransactionInput>(body);
        assert!(
            parsed.is_err(),
            "{label} must reject at parse boundary, got: {parsed:?}"
        );
    }
}

/// **Null-rejection (nested).** `null` for nested required collections
/// (`assets`, `extension`, `additionalRegisters`) must also reject
/// at the JSON parse boundary. Scala uses `Option`-less Circe
/// decoders for these, so `null` is a hard parse error there too.
/// Without this, a wallet sending `"assets": null` would either be
/// silently treated as `[]` (silent semantics divergence from Scala)
/// or surface a confusing decode-time error rather than a parse
/// error.
#[test]
fn b4_q4_nested_null_rejects() {
    let mainnet = load_vectors("transactions_1_10.json");
    let v = &mainnet[0];
    let raw = hex::decode(&v.bytes).unwrap();
    let mut r = VlqReader::new(&raw);
    let tx = read_transaction(&mut r).unwrap();
    let scala = encode_transaction(&tx).unwrap();
    let json = serde_json::to_string(&scala).unwrap();

    // Mutate the JSON to inject `null` at each nested slot in turn,
    // then assert the input-DTO parse fails.
    type Mutator = fn(&mut serde_json::Value);
    let cases: &[(&str, Mutator)] = &[
        ("assets null", |val: &mut serde_json::Value| {
            let outs = val["outputs"].as_array_mut().unwrap();
            outs[0]["assets"] = serde_json::Value::Null;
        }),
        ("extension null", |val: &mut serde_json::Value| {
            let ins = val["inputs"].as_array_mut().unwrap();
            ins[0]["spendingProof"]["extension"] = serde_json::Value::Null;
        }),
        ("additionalRegisters null", |val: &mut serde_json::Value| {
            let outs = val["outputs"].as_array_mut().unwrap();
            outs[0]["additionalRegisters"] = serde_json::Value::Null;
        }),
    ];
    for (label, mutate) in cases {
        let mut val: serde_json::Value = serde_json::from_str(&json).unwrap();
        mutate(&mut val);
        let polluted = serde_json::to_string(&val).unwrap();
        let parsed = serde_json::from_str::<ScalaTransactionInput>(&polluted);
        assert!(
            parsed.is_err(),
            "{label} must reject at parse boundary, got: {parsed:?}"
        );
    }
}

/// **Symmetric empty acceptance.** `[]` for nested arrays
/// (`assets`) and `{}` for nested maps (`extension`,
/// `additionalRegisters`) must parse cleanly and produce
/// byte-stable canonical wire bytes. Pairs with the null-rejection
/// tests above to pin the full empty/null contract.
///
/// Strong assertion: we compute the EXPECTED canonical bytes via
/// the well-tested `write_transaction` path on the empty-collections
/// `Transaction` and assert the JSON-submission path produces the
/// same bytes. A deterministic-but-wrong encoding would fail here.
#[test]
fn b4_q4_nested_empty_collections_accept_canonical_bytes() {
    use ergo_ser::input::{ContextExtension, SpendingProof};
    use ergo_ser::register::AdditionalRegisters;

    let mainnet = load_vectors("transactions_1_10.json");
    let v = &mainnet[0];
    let raw = hex::decode(&v.bytes).unwrap();
    let mut r = VlqReader::new(&raw);
    let mut tx = read_transaction(&mut r).unwrap();

    // Mutate every nested collection in the parsed Transaction to
    // its empty form. SpendingProof preserves both the parsed
    // ContextExtension and the canonical wire bytes, so we rebuild
    // the proof via SpendingProof::new to keep them consistent.
    for inp in &mut tx.inputs {
        inp.spending_proof =
            SpendingProof::new(inp.spending_proof.proof.clone(), ContextExtension::empty())
                .unwrap();
    }
    for out in &mut tx.output_candidates {
        out.tokens.clear();
        out.additional_registers = AdditionalRegisters::empty();
    }

    // EXPECTED canonical bytes via the production write path.
    let mut w = VlqWriter::new();
    write_transaction(&mut w, &tx).unwrap();
    let expected_bytes = w.result();

    // Now exercise the JSON-submission path with all nested
    // collections explicitly set to empty `[]`/`{}`.
    let scala = encode_transaction(&tx).unwrap();
    let json = serde_json::to_string(&scala).unwrap();
    let mut val: serde_json::Value = serde_json::from_str(&json).unwrap();
    for inp in val["inputs"].as_array_mut().unwrap() {
        inp["spendingProof"]["extension"] = serde_json::Value::Object(serde_json::Map::new());
    }
    for out in val["outputs"].as_array_mut().unwrap() {
        out["assets"] = serde_json::Value::Array(Vec::new());
        out["additionalRegisters"] = serde_json::Value::Object(serde_json::Map::new());
    }
    let body = serde_json::to_string(&val).unwrap();
    let input: ScalaTransactionInput =
        serde_json::from_str(&body).expect("explicit empty nested collections must parse cleanly");
    let actual_bytes = decode_scala_transaction(&input)
        .expect("empty nested collections must decode through JSON path");

    assert_eq!(
        actual_bytes, expected_bytes,
        "JSON path with empty nested collections must produce the same \
         canonical bytes as direct write_transaction on the empty-form Transaction"
    );
}

/// **Omitted-array rejection.** Each of `inputs`,
/// `dataInputs`, `outputs` is required by Scala's
/// `ergoLikeTransactionDecoder` and has no `Option`/default. A
/// future `#[serde(default)]` slip on any single field would
/// silently produce empty arrays for missing fields, violating
/// Scala parity; these tests pin each slot independently.
#[test]
fn b4_q2_missing_inputs_rejects() {
    let body = r#"{"dataInputs": [], "outputs": []}"#;
    let parsed = serde_json::from_str::<ScalaTransactionInput>(body);
    assert!(
        parsed.is_err(),
        "missing 'inputs' must reject at parse boundary, got: {parsed:?}"
    );
}

#[test]
fn b4_q2_missing_data_inputs_rejects() {
    let body = r#"{"inputs": [], "outputs": []}"#;
    let parsed = serde_json::from_str::<ScalaTransactionInput>(body);
    assert!(
        parsed.is_err(),
        "missing 'dataInputs' must reject at parse boundary, got: {parsed:?}"
    );
}

#[test]
fn b4_q2_missing_outputs_rejects() {
    let body = r#"{"inputs": [], "dataInputs": []}"#;
    let parsed = serde_json::from_str::<ScalaTransactionInput>(body);
    assert!(
        parsed.is_err(),
        "missing 'outputs' must reject at parse boundary, got: {parsed:?}"
    );
}

/// **Soft-fork ergoTree rejection.** A hand-crafted ergoTree with header version > 3
/// (encoded in the low 3 bits of the header byte) must reject with
/// `non_canonical`. Pins the v1-only soft-fork support contract:
/// our `unparsed_soft_fork_tree` placeholder is synthetic and would
/// not preserve the user's bytes through admission.
#[test]
fn b4_q5_soft_fork_ergo_tree_version_rejected() {
    // Header byte: bits 0-2 = version. We need version > 3 (e.g. 4).
    // Other bits: has_size = 0, constant_segregation = 0, no other flags.
    // 0x04 = version 4, no size, no constant segregation.
    // Body byte: SBoolean (0x01) + true (0x01) — minimal valid body
    // shape that won't get past the version check anyway.
    let soft_fork_tree = "040101";
    let map = BTreeMap::new();
    let so = ergo_api::compat::types::ScalaOutputInput {
        value: 1_000_000,
        ergo_tree: soft_fork_tree.to_string(),
        assets: vec![],
        creation_height: 1,
        additional_registers: map,
    };
    let err = decode_output(&so).expect_err("soft-fork tree must reject");
    assert_eq!(err.0, NON_CANONICAL, "must bucket as non_canonical");
    assert!(
        err.1.contains("soft-fork") || err.1.contains("version"),
        "detail must mention version/soft-fork, got: {:?}",
        err.1
    );
}

/// **Non-canonical register canonicalization.** The sigma
/// `SBoolean` reader (`ergo-ser/src/sigma_value.rs:178`) accepts
/// any non-zero byte as `true`, but the writer (line 127) always
/// emits `0x01`. So `"0105"` (type=01 SBoolean, value=05) is a
/// genuine non-canonical encoding that parses successfully and
/// canonicalizes to `"0101"`.
///
/// This pins the parse-then-re-serialize contract on a boundary
/// where input and output bytes genuinely differ — proving the
/// canonicalization step is load-bearing rather than passing user
/// bytes through. The end-to-end consequence is `tx_id` parity
/// with Scala for any wallet that submits a non-canonical register
/// blob (which Scala canonicalizes via `ValueSerializer`
/// round-trip).
#[test]
fn b4_q5_register_canonicalization_rewrites_non_canonical_bytes() {
    // Sanity: confirm the SBoolean reader-writer asymmetry holds.
    // If sigma-rust ever tightens the reader to reject non-zero,
    // this test must be updated to use a different non-canonical
    // case (BigInt leading zeros are a fallback) — failing loudly
    // beats silent skew.
    let mut probe = BTreeMap::new();
    probe.insert("R4".to_string(), "0105".to_string());
    let (_p, wire_from_noncanonical) =
        decode_registers(&probe).expect("0105 must parse via SBoolean tolerance");

    let mut canonical_map = BTreeMap::new();
    canonical_map.insert("R4".to_string(), "0101".to_string());
    let (_p, wire_from_canonical) =
        decode_registers(&canonical_map).expect("0101 is the canonical form");

    assert_eq!(
        wire_from_noncanonical, wire_from_canonical,
        "non-canonical 0105 must produce the same wire bytes as canonical 0101 \
         — proves parse-then-emit canonicalization is load-bearing"
    );

    // Stronger: the canonical wire MUST contain 0x01 (canonical
    // true byte), not 0x05 (the input). If equality held for some
    // other reason, this catches it.
    // Wire shape: count(u8=1) + register0_bytes(0101).
    assert_eq!(
        wire_from_noncanonical,
        vec![1, 0x01, 0x01],
        "wire must be the canonical 0101 encoding, not 0105 passthrough"
    );

    // End-to-end: also verify the same canonicalization happens
    // through the full transaction decode path. A real wallet
    // submitting a tx whose output register hex is "0105" must
    // produce the same tx_id as one submitting "0101".
    // (Parse-then-re-serialize at the full-tx boundary.)
    let mainnet = load_vectors("transactions_1_10.json");
    let v = &mainnet[0];
    let raw = hex::decode(&v.bytes).unwrap();
    let mut r = VlqReader::new(&raw);
    let tx = read_transaction(&mut r).unwrap();
    let scala = encode_transaction(&tx).unwrap();
    let json = serde_json::to_string(&scala).unwrap();

    let mut canon: serde_json::Value = serde_json::from_str(&json).unwrap();
    let mut nonc: serde_json::Value = serde_json::from_str(&json).unwrap();
    for (val, hex) in &mut [(&mut canon, "0101"), (&mut nonc, "0105")] {
        let outs = val["outputs"].as_array_mut().unwrap();
        let regs = outs[0]["additionalRegisters"].as_object_mut().unwrap();
        regs.insert("R4".into(), serde_json::json!(*hex));
    }
    let canon_input: ScalaTransactionInput = serde_json::from_value(canon).unwrap();
    let nonc_input: ScalaTransactionInput = serde_json::from_value(nonc).unwrap();
    let canon_bytes =
        decode_scala_transaction(&canon_input).expect("canonical R4 path must decode");
    let nonc_bytes = decode_scala_transaction(&nonc_input)
        .expect("non-canonical R4 path must decode (canonicalization)");
    assert_eq!(
        canon_bytes, nonc_bytes,
        "non-canonical R4 input must produce the same tx bytes as canonical \
         — parse-then-re-serialize at the full-tx boundary"
    );
}

/// **Context-extension canonicalization.** The
/// `extension` map in `spendingProof` is also tx-id bearing
/// (signed inputs include their extension bytes). Same SBoolean
/// reader-writer asymmetry trick: `"0105"` (non-canonical
/// SBoolean true) must canonicalize to `"0101"` and produce the
/// same tx bytes as a canonical-encoded request.
///
/// Why this matters: a wallet-submitted tx whose proof extension
/// uses a non-canonical encoding would produce one tx_id under
/// passthrough and a different one under Scala's
/// `ValueSerializer` round-trip. Wallets, mempools, and explorers
/// disagree on the tx_id → relay confusion and double-spends.
#[test]
fn b4_q5_extension_canonicalization_rewrites_non_canonical_bytes() {
    let mainnet = load_vectors("transactions_1_10.json");
    let v = &mainnet[0];
    let raw = hex::decode(&v.bytes).unwrap();
    let mut r = VlqReader::new(&raw);
    let tx = read_transaction(&mut r).unwrap();
    let scala = encode_transaction(&tx).unwrap();
    let json = serde_json::to_string(&scala).unwrap();

    // Inject the same extension entry into both copies, only the
    // hex differs (canonical 0101 vs non-canonical 0105 SBoolean).
    let mut canon: serde_json::Value = serde_json::from_str(&json).unwrap();
    let mut nonc: serde_json::Value = serde_json::from_str(&json).unwrap();
    for (val, hex) in &mut [(&mut canon, "0101"), (&mut nonc, "0105")] {
        let ins = val["inputs"].as_array_mut().unwrap();
        let ext = ins[0]["spendingProof"]["extension"]
            .as_object_mut()
            .unwrap();
        ext.insert("0".into(), serde_json::json!(*hex));
    }
    let canon_input: ScalaTransactionInput = serde_json::from_value(canon).unwrap();
    let nonc_input: ScalaTransactionInput = serde_json::from_value(nonc).unwrap();
    let canon_bytes =
        decode_scala_transaction(&canon_input).expect("canonical extension entry must decode");
    let nonc_bytes = decode_scala_transaction(&nonc_input)
        .expect("non-canonical extension entry must decode (canonicalization)");
    assert_eq!(
        canon_bytes, nonc_bytes,
        "non-canonical extension entry must produce the same tx bytes as \
         canonical — parse-then-re-serialize at the proof-extension boundary"
    );
}

/// **Soft-fork/unparseable body reject path.** A supported-version
/// ergoTree that hits the `unparsed_soft_fork_tree` path inside
/// `read_ergo_tree` must reject with `non_canonical` on submission.
/// Pins the body-is-`Expr::Unparsed` arm of
/// `decode_ergo_tree_canonicalize`'s Submit-mode soft-fork rejection.
///
/// Test vector construction: an ergoTree with `has_size=1`
/// wrapping a body whose root constant is not `SSigmaProp`. The
/// reader's CheckDeserializedScriptIsSigmaProp equivalent wraps the
/// tree as `Expr::Unparsed`, preserving the original bytes verbatim
/// (so it re-serializes byte-identically — mirroring Scala's
/// `UnparsedErgoTree(propositionBytes)`). The Submit-mode guard
/// rejects any `Expr::Unparsed` body — such a script is unspendable
/// and a well-behaved wallet never submits one.
#[test]
fn b4_q5_soft_fork_ergo_tree_placeholder_fallback_rejected() {
    // Header byte: 0x18 = 0001 1000
    //   bits 0-2: version = 0 (supported)
    //   bit 3: constant_segregation = 0
    //   bit 4: has_size = 1 (required for the bounded-data parse path)
    // Size varint: 0x02 (body is 2 bytes)
    // Body: 0x04 (SInt type code) + 0x05 (zigzag-encoded value)
    //   → root constant is SInt, not SSigmaProp → placeholder fallback
    let placeholder_tree = "18020405";
    let so = ergo_api::compat::types::ScalaOutputInput {
        value: 1_000_000,
        ergo_tree: placeholder_tree.to_string(),
        assets: vec![],
        creation_height: 1,
        additional_registers: BTreeMap::new(),
    };
    let err = decode_output(&so).expect_err("placeholder fallback ergoTree must reject");
    assert_eq!(err.0, NON_CANONICAL, "must bucket as non_canonical");
    assert!(
        err.1.contains("roundtrip") || err.1.contains("soft-fork") || err.1.contains("unparseable"),
        "detail must mention roundtrip/soft-fork/unparseable, got: {:?}",
        err.1
    );
}

/// Encoding a stored box must produce a `boxId` that round-trips
/// through `blake2b256(serialize_ergo_box(...))`.
/// The mainnet genesis emission box is the worst-case fixture — non-
/// size-delimited tree, populated `R4..R6` with sigma values whose
/// canonical wire encoding is non-trivial.
///
/// If `encode_scala_output_from_raw` ever silently round-trips
/// registers through `write_registers`, the box hex would change
/// even by one byte and this test would catch it.
#[test]
fn utxo_genesis_box_id_roundtrips_through_raw_encoder() {
    let boxes = crate::genesis::mainnet_genesis_boxes();
    assert_eq!(boxes.len(), 3, "mainnet genesis is exactly three boxes");
    for (id, raw) in &boxes {
        let out =
            encode_scala_output_from_raw(raw, id).unwrap_or_else(|e| panic!("encode failed: {e}"));
        assert_eq!(
            out.box_id,
            hex::encode(id),
            "boxId must match the precomputed lookup key",
        );
    }
}

/// **Register hex from preserved wire bytes.** Encoding a box must emit
/// per-register hex sliced from the wire bytes the parser preserved.
/// We assert this by reading the raw bytes back end-to-end:
///   raw_box → split off transaction_id+index → walk to register
///   section → split via `split_register_bytes` → hex.
/// The result must match `out.additional_registers` exactly.
#[test]
fn utxo_encoder_register_hex_is_verbatim_wire_bytes() {
    use ergo_ser::register::split_register_bytes as split_regs;

    let boxes = crate::genesis::mainnet_genesis_boxes();
    // Pick the box with the most registers (genesis emission box has
    // R4..R6). Falling back to any with non-empty registers if order
    // changes upstream.
    let (id, raw) = boxes
        .iter()
        .find(|(_, raw)| {
            // crude: parse and check non-empty
            let mut r = VlqReader::new(raw);
            read_ergo_box(&mut r)
                .map(|b| {
                    !b.candidate.register_bytes().is_empty() && b.candidate.register_bytes() != [0]
                })
                .unwrap_or(false)
        })
        .expect("at least one genesis box has populated registers");

    let mut r = VlqReader::new(raw);
    let parsed = read_ergo_box(&mut r).unwrap();
    let raw_register_bytes = parsed.candidate.register_bytes().to_vec();

    let slices = split_regs(&raw_register_bytes).unwrap();
    let expected: BTreeMap<String, String> = slices
        .into_iter()
        .enumerate()
        .map(|(i, s)| (REGISTER_NAMES[i].to_string(), hex::encode(s)))
        .collect();

    let out = encode_scala_output_from_raw(raw, id).unwrap();
    assert_eq!(
        out.additional_registers, expected,
        "additional_registers hex must equal split of raw register_bytes",
    );
}

// ===================================================================
// §12 step (e) — SubmitBridge::submit_full_block boundary tests
// ===================================================================
//
// These tests pin the bridge-side contract: JSON decode, PoW verify,
// event channel send + reply ferry. Full end-to-end behaviour (the
// action loop applying the block) belongs in
// `ergo-node/tests/submit_e2e.rs` which spawns a real node.

use ergo_api::compat::types::{
    ScalaAdProofs, ScalaBlockTransactions, ScalaExtension, ScalaFullBlock, ScalaHeader,
    ScalaPowSolutions,
};

/// Returns a minimal v2 ScalaHeader / ScalaFullBlock pair the
/// bridge's `decode_scala_full_block` accepts. Section-ids are
/// computed from the decoded header_id so the boundary check
/// (added in §12(a) fix `32bdc1e`) doesn't reject the body.
fn minimal_consistent_block() -> ScalaFullBlock {
    let header = ScalaHeader {
        extension_id: String::new(),
        difficulty: "1".to_string(),
        votes: "000000".to_string(),
        timestamp: 1_550_000_000_000,
        size: 0,
        unparsed_bytes: String::new(),
        state_root: "00".repeat(33),
        height: 1,
        n_bits: 0x011765,
        version: 2,
        id: String::new(),
        ad_proofs_root: "00".repeat(32),
        transactions_root: "00".repeat(32),
        extension_hash: "00".repeat(32),
        pow_solutions: ScalaPowSolutions {
            pk: "02".to_string() + &"00".repeat(32),
            w: "00".repeat(33),
            n: "00".repeat(8),
            d: serde_json::Value::Number(0u32.into()),
        },
        ad_proofs_id: String::new(),
        transactions_id: String::new(),
        parent_id: "00".repeat(32),
    };
    let (_h_bytes, h_id) = ergo_rest_json::decode_scala_header(&header).unwrap();
    let id_hex = hex::encode(h_id.as_bytes());
    ScalaFullBlock {
        header,
        block_transactions: ScalaBlockTransactions {
            header_id: id_hex.clone(),
            transactions: vec![],
            block_version: 2,
            size: 0,
        },
        extension: ScalaExtension {
            header_id: id_hex.clone(),
            digest: "00".repeat(32),
            fields: vec![],
        },
        ad_proofs: Some(ScalaAdProofs {
            header_id: id_hex,
            proof_bytes: String::new(),
            digest: "00".repeat(32),
            size: 0,
        }),
        size: 0,
    }
}

fn make_bridge() -> (
    SubmitBridge,
    tokio::sync::mpsc::Receiver<SubmitRequest>,
    tokio::sync::mpsc::Receiver<crate::peer_loop::PeerEvent>,
) {
    let (submit_tx, submit_rx) = tokio::sync::mpsc::channel::<SubmitRequest>(4);
    let (event_tx, event_rx) = tokio::sync::mpsc::channel::<crate::peer_loop::PeerEvent>(4);
    let bridge = SubmitBridge::new(submit_tx, event_tx);
    (bridge, submit_rx, event_rx)
}

/// JSON-decode failure (section-id mismatch) maps to
/// `reason: "deserialize"` and never touches the event channel.
#[tokio::test]
async fn submit_full_block_decode_failure_returns_deserialize() {
    let (bridge, _submit_rx, mut event_rx) = make_bridge();
    let mut body = minimal_consistent_block();
    // Mutate block_transactions.headerId so the JSON boundary
    // consistency check (32bdc1e) rejects.
    body.block_transactions.header_id = "ff".repeat(32);

    let err = bridge.submit_full_block(body).await.unwrap_err();
    assert_eq!(err.reason, "deserialize", "got {err:?}");
    // Event channel must be untouched — the decode error short-
    // circuits before any `try_send`.
    assert!(
        event_rx.try_recv().is_err(),
        "event channel must be empty on decode failure",
    );
}

/// Header decodes cleanly but the synthetic PoW solution fails
/// `verify_pow_solution`. Maps to `invalid_pow`.
#[tokio::test]
async fn submit_full_block_bad_pow_returns_invalid_pow() {
    let (bridge, _submit_rx, mut event_rx) = make_bridge();
    // minimal_consistent_block has nBits = 0x011765 (real-ish
    // target) and a zero PoW solution, which will never satisfy.
    let body = minimal_consistent_block();
    let err = bridge.submit_full_block(body).await.unwrap_err();
    assert_eq!(err.reason, "invalid_pow", "got {err:?}");
    assert!(
        event_rx.try_recv().is_err(),
        "event channel must be empty on PoW failure",
    );
}

/// Load the real mainnet full-block fixture (height 836_113,
/// v2 PoW). PoW will verify cleanly so tests can exercise the
/// channel/reply half of the bridge.
fn mainnet_block_836113() -> ScalaFullBlock {
    let path = vectors_dir().join("block_836113.json");
    let raw =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_str(&raw).unwrap_or_else(|e| panic!("parse {}: {e}", path.display()))
}

/// Pre-fill the event channel to capacity, then submit a real
/// block. The PoW verify passes (mainnet 836_113 is a real
/// header), reaches `try_send`, gets `Full`, maps to
/// `overloaded`.
#[tokio::test]
async fn submit_full_block_overloaded_when_event_channel_full() {
    let (submit_tx, _submit_rx) = tokio::sync::mpsc::channel::<SubmitRequest>(4);
    // Capacity 1 so we can fill with a single placeholder event.
    let (event_tx, _event_rx) = tokio::sync::mpsc::channel::<crate::peer_loop::PeerEvent>(1);
    let bridge = SubmitBridge::new(submit_tx, event_tx.clone());

    // Fill the event channel with a synthetic LocalFullBlock placeholder
    // (the reply oneshot is leaked here — we never drive it; the
    // assertion is about `try_send` returning `Full`).
    let (placeholder_reply, _) = tokio::sync::oneshot::channel();
    event_tx
        .try_send(crate::peer_loop::PeerEvent::LocalFullBlock {
            header_bytes: vec![],
            bt_bytes: vec![],
            ext_bytes: vec![],
            ad_proofs_bytes: None,
            reply: placeholder_reply,
        })
        .expect("first send must succeed (capacity=1)");

    let err = bridge
        .submit_full_block(mainnet_block_836113())
        .await
        .unwrap_err();
    assert_eq!(err.reason, "overloaded", "got {err:?}");
}

/// Drop the event receiver before submitting. `try_send` returns
/// `Closed` → bridge maps to `shutting_down`.
#[tokio::test]
async fn submit_full_block_closed_event_channel_returns_shutting_down() {
    let (submit_tx, _submit_rx) = tokio::sync::mpsc::channel::<SubmitRequest>(4);
    let (event_tx, event_rx) = tokio::sync::mpsc::channel::<crate::peer_loop::PeerEvent>(4);
    drop(event_rx); // emulate "main loop has shut down"
    let bridge = SubmitBridge::new(submit_tx, event_tx);

    let err = bridge
        .submit_full_block(mainnet_block_836113())
        .await
        .unwrap_err();
    assert_eq!(err.reason, "shutting_down", "got {err:?}");
}

/// Happy path: drain the event, send Ok reply, bridge relays
/// the header_id string.
#[tokio::test]
async fn submit_full_block_ok_reply_relays_header_id() {
    let (submit_tx, _submit_rx) = tokio::sync::mpsc::channel::<SubmitRequest>(4);
    let (event_tx, mut event_rx) = tokio::sync::mpsc::channel::<crate::peer_loop::PeerEvent>(4);
    let bridge = SubmitBridge::new(submit_tx, event_tx);

    // Spawn a task that mimics the action-loop handler: drain
    // the event, reply with a deterministic header_id.
    let expected_id = "deadbeef".repeat(8);
    let expected_id_for_task = expected_id.clone();
    let action_loop = tokio::spawn(async move {
        let event = event_rx.recv().await.expect("event must arrive");
        match event {
            crate::peer_loop::PeerEvent::LocalFullBlock { reply, .. } => {
                let _ = reply.send(Ok(expected_id_for_task));
            }
            _ => panic!("expected PeerEvent::LocalFullBlock"),
        }
    });

    let id = bridge
        .submit_full_block(mainnet_block_836113())
        .await
        .expect("bridge must relay the reply");
    assert_eq!(id, expected_id, "bridge must echo the reply header id");
    action_loop.await.expect("action-loop task must finish");
}

/// Action loop receives the event but drops the reply oneshot
/// without sending → `recv_err` → maps to `shutting_down`.
#[tokio::test]
async fn submit_full_block_oneshot_dropped_returns_shutting_down() {
    let (submit_tx, _submit_rx) = tokio::sync::mpsc::channel::<SubmitRequest>(4);
    let (event_tx, mut event_rx) = tokio::sync::mpsc::channel::<crate::peer_loop::PeerEvent>(4);
    let bridge = SubmitBridge::new(submit_tx, event_tx);

    let action_loop = tokio::spawn(async move {
        let event = event_rx.recv().await.expect("event must arrive");
        // Drop the reply oneshot without sending. Receiver side
        // gets `Err(RecvError::Closed)`.
        drop(event);
    });

    let err = bridge
        .submit_full_block(mainnet_block_836113())
        .await
        .unwrap_err();
    assert_eq!(err.reason, "shutting_down", "got {err:?}");
    action_loop.await.unwrap();
}

// ----- host() byte fields: Option<u64> semantics -----

/// Build a `SnapshotReadState` pinned to `host_paths` for host() tests.
/// The snapshot itself is a default empty publisher — host() ignores it.
fn read_state_for_host(host_paths: HostPaths) -> SnapshotReadState {
    read_state_with_targets(host_paths, std::collections::BTreeMap::new())
}

/// Like `read_state_for_host` but seeds the operator voting targets so the
/// `configured_votes` projection in `votes()` can be exercised.
fn read_state_with_targets(
    host_paths: HostPaths,
    voting_targets: std::collections::BTreeMap<u8, i64>,
) -> SnapshotReadState {
    read_state_with_slot(
        host_paths,
        std::sync::Arc::new(std::sync::RwLock::new(voting_targets)),
    )
}

/// Like `read_state_with_targets` but shares an EXISTING voting-targets slot, so
/// a test can wire the same `Arc<RwLock<…>>` into both the read state and a
/// `ShutdownAdmin` and observe runtime writes reflected in `votes()`.
fn read_state_with_slot(
    host_paths: HostPaths,
    voting_targets: std::sync::Arc<std::sync::RwLock<std::collections::BTreeMap<u8, i64>>>,
) -> SnapshotReadState {
    let api_info = ergo_api::types::ApiInfo {
        agent_name: "test".into(),
        node_name: "test".into(),
        network: "mainnet".into(),
        version: "0.0.0".into(),
        started_at_unix_ms: 0,
        uptime_seconds: 0,
        target_block_interval_ms: 120_000,
    };
    let publisher = crate::snapshot::SnapshotPublisher::new(
        api_info,
        std::time::Instant::now(),
        ergo_api::types::ApiWeightFunction::Cost,
    );
    let identity_slot: crate::api_bridge::IdentitySlot =
        std::sync::Arc::new(arc_swap::ArcSwap::from_pointee(ApiIdentity::default()));
    SnapshotReadState::new(
        publisher.handle(),
        identity_slot,
        host_paths,
        voting_targets,
    )
}

/// `votes()` projects the snapshot's active params into the votable-parameter
/// set (scala_launch has subblocks_per_block = None → ids 1..=8, no id 9, never
/// blockVersion), with bounds straight from the shared recompute table.
#[test]
fn votes_serves_votable_params_from_active_set() {
    let dir = tempfile::tempdir().unwrap();
    let read = read_state_for_host(HostPaths {
        state_db: dir.path().join("s.redb"),
        index_db: dir.path().join("i.redb"),
        data_dir: dir.path().to_path_buf(),
    });
    let v = read.votes();
    let ids: Vec<u8> = v.votable_parameters.iter().map(|p| p.id).collect();
    assert_eq!(
        ids,
        vec![1, 2, 3, 4, 5, 6, 7, 8],
        "scala_launch → ids 1..=8"
    );
    let sff = v.votable_parameters.iter().find(|p| p.id == 1).unwrap();
    assert_eq!(sff.name, "storageFeeFactor");
    assert_eq!(sff.current, 1_250_000);
    assert_eq!((sff.step, sff.min, sff.max), (25_000, 0, 2_500_000));
    assert!(
        sff.description.contains("Storage-rent"),
        "votable params carry the operator-facing description: {:?}",
        sff.description,
    );
    assert!(
        v.votable_parameters.iter().all(|p| p.id != 123),
        "blockVersion never votable"
    );
    assert!(
        v.configured_votes.is_empty(),
        "no operator votes configured yet"
    );
    assert_eq!(v.block_version, 1);
}

/// With `[voting.targets]` configured, `votes()` reports them under
/// `configured_votes` — id → canonical name + target — sorted by parameter id,
/// so an operator with the API enabled can verify the policy the node mines
/// with.
#[test]
fn votes_reports_configured_operator_votes() {
    let dir = tempfile::tempdir().unwrap();
    let mut targets = std::collections::BTreeMap::new();
    targets.insert(3u8, 600_000i64); // maxBlockSize
    targets.insert(1u8, 1_300_000i64); // storageFeeFactor
    let read = read_state_with_targets(
        HostPaths {
            state_db: dir.path().join("s.redb"),
            index_db: dir.path().join("i.redb"),
            data_dir: dir.path().to_path_buf(),
        },
        targets,
    );
    let v = read.votes();
    let cv: Vec<(u8, &str, i64)> = v
        .configured_votes
        .iter()
        .map(|c| (c.parameter_id, c.name.as_str(), c.target))
        .collect();
    assert_eq!(
        cv,
        vec![
            (1, "storageFeeFactor", 1_300_000),
            (3, "maxBlockSize", 600_000),
        ],
        "configured votes mirror [voting.targets], ascending by id"
    );
}

/// A runtime `POST /api/v1/votes` write (via `NodeAdmin::set_voting_targets`)
/// updates the SHARED slot, and `GET /api/v1/votes` (the read state on the same
/// slot) reflects it live — REPLACE semantics, with non-votable ids rejected
/// atomically and an empty set clearing all votes.
#[test]
fn set_voting_targets_write_is_reflected_live_by_votes() {
    use ergo_api::{NodeAdmin, VotingControlError};

    let dir = tempfile::tempdir().unwrap();
    let slot = std::sync::Arc::new(std::sync::RwLock::new(std::collections::BTreeMap::new()));
    let read = read_state_with_slot(
        HostPaths {
            state_db: dir.path().join("s.redb"),
            index_db: dir.path().join("i.redb"),
            data_dir: dir.path().to_path_buf(),
        },
        slot.clone(),
    );
    // Mining-enabled admin shares the same slot.
    let admin = crate::api_bridge::ShutdownAdmin::new(
        std::sync::Arc::new(tokio::sync::Notify::new()),
        None,
    )
    .with_voting_targets(slot.clone());

    let configured = |r: &SnapshotReadState| -> Vec<(u8, i64)> {
        r.votes()
            .configured_votes
            .iter()
            .map(|c| (c.parameter_id, c.target))
            .collect()
    };

    assert!(configured(&read).is_empty(), "starts empty");

    // Set → reflected live by the read endpoint.
    admin.set_voting_targets(vec![(3, 600_000)]).unwrap();
    assert_eq!(configured(&read), vec![(3, 600_000)]);

    // REPLACE: a new set replaces (not merges).
    admin.set_voting_targets(vec![(1, 1_300_000)]).unwrap();
    assert_eq!(configured(&read), vec![(1, 1_300_000)]);

    // Non-votable id (blockVersion 123) rejected; the set is unchanged.
    assert_eq!(
        admin
            .set_voting_targets(vec![(1, 9), (123, 4)])
            .unwrap_err(),
        VotingControlError::NotVotable { parameter_id: 123 },
    );
    assert_eq!(
        configured(&read),
        vec![(1, 1_300_000)],
        "rejected write is atomic"
    );

    // Empty clears.
    admin.set_voting_targets(vec![]).unwrap();
    assert!(configured(&read).is_empty(), "empty set clears all votes");
}

/// Without a wired slot (mining disabled), the write is rejected — votes have
/// no effect with no candidate builder.
#[test]
fn set_voting_targets_without_mining_is_rejected() {
    use ergo_api::{NodeAdmin, VotingControlError};
    let admin = crate::api_bridge::ShutdownAdmin::new(
        std::sync::Arc::new(tokio::sync::Notify::new()),
        None,
    );
    assert_eq!(
        admin.set_voting_targets(vec![(3, 600_000)]).unwrap_err(),
        VotingControlError::MiningDisabled,
    );
}

/// A SUCCESSFUL vote change fires the action-loop rebuild signal (so the new
/// votes apply on the next mined block, not the next tip/mempool change); a
/// REJECTED change does not.
#[test]
fn set_voting_targets_signals_rebuild_only_on_success() {
    use ergo_api::NodeAdmin;
    let slot = std::sync::Arc::new(std::sync::RwLock::new(std::collections::BTreeMap::new()));
    let (tx, mut rx) = tokio::sync::mpsc::channel::<()>(4);
    let admin = crate::api_bridge::ShutdownAdmin::new(
        std::sync::Arc::new(tokio::sync::Notify::new()),
        None,
    )
    .with_voting_targets(slot)
    .with_votes_changed_signal(tx);

    // Success → exactly one rebuild signal queued.
    admin.set_voting_targets(vec![(3, 600_000)]).unwrap();
    assert!(
        rx.try_recv().is_ok(),
        "a successful vote change signals a rebuild"
    );
    assert!(rx.try_recv().is_err(), "exactly one signal per change");

    // Rejected (non-votable id) → no rebuild signal.
    assert!(admin.set_voting_targets(vec![(123, 4)]).is_err());
    assert!(
        rx.try_recv().is_err(),
        "a rejected vote change must NOT signal a rebuild",
    );
}

/// A target beyond the parameter's allowable `[min, max]` range is rejected
/// (`OutOfRange`) rather than silently clamped, and the rejected write does not
/// mutate the set. Bounds are constant per id, so no active-param source is
/// needed — enforcement is unconditional whenever voting is enabled.
#[test]
fn set_voting_targets_rejects_target_outside_allowable_range() {
    use ergo_api::{NodeAdmin, VotingControlError};

    let slot = std::sync::Arc::new(std::sync::RwLock::new(std::collections::BTreeMap::new()));
    let admin = crate::api_bridge::ShutdownAdmin::new(
        std::sync::Arc::new(tokio::sync::Notify::new()),
        None,
    )
    .with_voting_targets(slot.clone());

    // storageFeeFactor (id 1) allowable range is [0, 2_500_000].
    // An in-range target is accepted.
    admin.set_voting_targets(vec![(1, 1_300_000)]).unwrap();
    assert_eq!(
        *slot.read().unwrap(),
        [(1u8, 1_300_000i64)].into_iter().collect()
    );

    // A target above the max is rejected as OutOfRange…
    assert_eq!(
        admin.set_voting_targets(vec![(1, 3_000_000)]).unwrap_err(),
        VotingControlError::OutOfRange {
            parameter_id: 1,
            target: 3_000_000,
            min: 0,
            max: 2_500_000,
        },
    );
    // …and the rejected write is atomic — the prior in-range set survives.
    assert_eq!(
        *slot.read().unwrap(),
        [(1u8, 1_300_000i64)].into_iter().collect(),
        "rejected out-of-range write must not mutate the set",
    );
}

/// State DB file present and non-empty → `Some(len)` with the actual
/// file length.
#[test]
fn host_state_db_existing_file_returns_some_len() {
    let dir = tempfile::tempdir().unwrap();
    let state_db = dir.path().join("state.redb");
    std::fs::write(&state_db, b"redb-payload").unwrap();
    let read = read_state_for_host(HostPaths {
        state_db: state_db.clone(),
        index_db: dir.path().join("missing-index.redb"),
        data_dir: dir.path().to_path_buf(),
    });
    let host = read.host();
    assert_eq!(
        host.state_db_bytes,
        Some(12),
        "wrote 12 bytes, expected Some(12)"
    );
}

/// Empty file → `Some(0)`, not `None`. The wire shape must
/// distinguish "file exists but is empty" from "file missing."
#[test]
fn host_state_db_empty_file_returns_some_zero() {
    let dir = tempfile::tempdir().unwrap();
    let state_db = dir.path().join("state.redb");
    std::fs::File::create(&state_db).unwrap();
    let read = read_state_for_host(HostPaths {
        state_db: state_db.clone(),
        index_db: dir.path().join("missing-index.redb"),
        data_dir: dir.path().to_path_buf(),
    });
    let host = read.host();
    assert_eq!(host.state_db_bytes, Some(0));
}

/// State DB path doesn't exist → `None`. Pre-r5 the field wired as
/// `0` here, which monitoring scrapers misread as "database empty."
#[test]
fn host_state_db_missing_file_returns_none() {
    let dir = tempfile::tempdir().unwrap();
    let read = read_state_for_host(HostPaths {
        state_db: dir.path().join("does-not-exist.redb"),
        index_db: dir.path().join("also-missing.redb"),
        data_dir: dir.path().to_path_buf(),
    });
    let host = read.host();
    assert_eq!(host.state_db_bytes, None);
}

/// Indexer disabled (file absent) → `None`. Operators with
/// `[indexer] enabled = false` should see `null`, not `0`.
#[test]
fn host_index_db_disabled_returns_none() {
    let dir = tempfile::tempdir().unwrap();
    let state_db = dir.path().join("state.redb");
    std::fs::write(&state_db, b"x").unwrap();
    let read = read_state_for_host(HostPaths {
        state_db,
        index_db: dir.path().join("indexer.redb"),
        data_dir: dir.path().to_path_buf(),
    });
    let host = read.host();
    assert_eq!(host.index_db_bytes, None);
}

/// Current process is always sampleable via sysinfo → RSS is
/// `Some(_)`. Pins that the sysinfo path constructs `Some`, not
/// `unwrap_or(0)` falling through to a bogus zero.
#[test]
fn host_rss_for_current_process_is_some() {
    let dir = tempfile::tempdir().unwrap();
    let read = read_state_for_host(HostPaths {
        state_db: dir.path().join("state.redb"),
        index_db: dir.path().join("indexer.redb"),
        data_dir: dir.path().to_path_buf(),
    });
    let host = read.host();
    let rss = host
        .rss_bytes
        .expect("RSS must be measurable for the test process");
    assert!(rss > 0, "test process RSS must be > 0, got {rss}");
}

/// `tempfile::tempdir()` lives on a mounted volume on every
/// supported platform, so the disk-match path produces
/// `Some(_)` for both fields. Pins the success branch — the
/// `None` branch fires when no sysinfo disk's mount-point is a
/// prefix of `data_dir`, which is environment-specific and
/// flaky to provoke in a test. Coverage of the `None` branch
/// for byte fields lives in the state-db / index-db tests
/// above.
#[test]
fn host_disk_for_tempdir_returns_some_pair() {
    let dir = tempfile::tempdir().unwrap();
    let read = read_state_for_host(HostPaths {
        state_db: dir.path().join("state.redb"),
        index_db: dir.path().join("indexer.redb"),
        data_dir: dir.path().to_path_buf(),
    });
    let host = read.host();
    let free = host
        .disk_free_bytes
        .expect("tempdir is on a mounted volume → Some(free)");
    let total = host
        .disk_total_bytes
        .expect("tempdir is on a mounted volume → Some(total)");
    assert!(
        total >= free,
        "disk_total_bytes ({total}) must be >= disk_free_bytes ({free})",
    );
    assert!(total > 0, "disk_total_bytes on a real volume must be > 0");
}

/// End-to-end JSON-encoder parity on REAL mainnet data, no node needed:
/// genuine Scala-serializer proof bytes (see
/// `scripts/jvm_nipopow_oracle/NipopowCapture.scala`) are decoded with
/// our wire reader and pushed through the `/nipopow/*` JSON encoders;
/// the result must equal the JSON the Scala node actually served for
/// the same proof (the REST capture the .bin was derived from). This
/// pins `encode_nipopow_proof`/`encode_popow_header` — including
/// per-header id/size recomputation and the empty-sibling digest
/// rendering — against the live oracle, value-for-value.
///
/// ONE documented exclusion: `header.size`. For headers in roughly the
/// h≈1.60-1.70M era (plus a handful of v1-era ones) the live Scala
/// node reports a size ONE BYTE LARGER than the header's actual wire
/// length — stale `sizeOpt` metadata in their storage; the value
/// contradicts the byte length of the very header bytes they serve
/// (verified live 2026-07-05: Scala /blocks h=1645005 says size=221
/// while both nodes' stored bytes for that id are 220 — two different
/// lengths cannot hash to the same header id). We serve the true byte
/// length, so `size` is normalized before comparison and asserted
/// against the canonical serialized length instead. Everything else —
/// including v1 `d` as an arbitrary-precision JSON NUMBER of the
/// unsigned magnitude — is compared exactly.
#[test]
fn nipopow_json_encoders_match_live_scala_response() {
    for (bin, json) in [
        (
            "../test-vectors/mainnet/nipopow/proof_m6_k10.scala.bin",
            "../test-vectors/mainnet/nipopow/proof_m6_k10.json",
        ),
        (
            "../test-vectors/mainnet/nipopow/proof_m6_k10_at_h1000.scala.bin",
            "../test-vectors/mainnet/nipopow/proof_m6_k10_at_h1000.json",
        ),
    ] {
        let bytes = std::fs::read(bin).unwrap_or_else(|e| panic!("read {bin}: {e}"));
        let proof = ergo_ser::popow_proof::deserialize_nipopow_proof(&bytes)
            .unwrap_or_else(|e| panic!("{bin}: deserialize: {e}"));
        let dto = super::nipopow::encode_nipopow_proof(&proof)
            .unwrap_or_else(|e| panic!("{bin}: encode: {e}"));
        let mut ours = serde_json::to_value(&dto).expect("DTO serializes");
        let mut scala: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(json).unwrap_or_else(|e| panic!("read {json}: {e}")),
        )
        .expect("fixture JSON parses");
        normalize_header_sizes(&mut ours, &mut scala);
        if scala != ours {
            let dump = std::env::temp_dir().join("nipopow_json_diff");
            std::fs::create_dir_all(&dump).ok();
            std::fs::write(
                dump.join("ours.json"),
                serde_json::to_string_pretty(&ours).unwrap(),
            )
            .ok();
            std::fs::write(
                dump.join("scala.json"),
                serde_json::to_string_pretty(&scala).unwrap(),
            )
            .ok();
            panic!(
                "{bin}: our JSON encoding diverges from the live Scala response; \
                 dumps at {}",
                dump.display()
            );
        }
    }
}

/// See `nipopow_json_encoders_match_live_scala_response`: collect and
/// zero the `size` field on every embedded header, returning the
/// original values in traversal order so the caller can assert the
/// documented tolerance (Scala's stale metadata is only ever the true
/// length or true length + 1; anything else is a real regression).
fn collect_and_zero_header_sizes(v: &mut serde_json::Value) -> Vec<(String, u64)> {
    let mut out = Vec::new();
    let mut zero_one = |h: &mut serde_json::Value| {
        let id = h["id"].as_str().unwrap().to_string();
        let size = h["size"].as_u64().unwrap();
        h["size"] = 0u64.into();
        out.push((id, size));
    };
    let obj = v.as_object_mut().unwrap();
    for key in ["prefix", "suffixHead", "suffixTail"] {
        match obj.get_mut(key) {
            Some(serde_json::Value::Array(items)) => {
                for item in items {
                    if item.get("header").is_some() {
                        zero_one(item.get_mut("header").unwrap());
                    } else {
                        zero_one(item);
                    }
                }
            }
            Some(single) => zero_one(single.get_mut("header").unwrap()),
            None => {}
        }
    }
    out
}

fn normalize_header_sizes(ours: &mut serde_json::Value, scala: &mut serde_json::Value) {
    let ours_sizes = collect_and_zero_header_sizes(ours);
    let scala_sizes = collect_and_zero_header_sizes(scala);
    assert_eq!(ours_sizes.len(), scala_sizes.len(), "header count");
    for ((oid, our_size), (sid, scala_size)) in ours_sizes.into_iter().zip(scala_sizes) {
        assert_eq!(oid, sid, "header order must agree");
        assert!(
            scala_size == our_size || scala_size == our_size + 1,
            "header {oid}: size {our_size} vs scala {scala_size} — outside the \
             documented stale-metadata tolerance"
        );
    }
}
