//! Oracle-parity for the ErgoTree header-version gate, keyed to the ACTIVATED
//! script version (issue #327).
//!
//! Scala's `deserializeErgoTree` runs `VersionContext.withVersions(activated,
//! treeVersion)`, whose `require(activatedVersion < JitActivationVersion ||
//! ergoTreeVersion <= activatedVersion)` (`VersionContext.scala:20`) is re-thrown
//! as a `SerializerException` — a HARD reject, size bit or not — but is INERT
//! below `JitActivationVersion = 2`. So the same bytes flip between ACCEPT and
//! REJECT across activated versions, and the node's box-script gate
//! (`check_tree_version_supported`, alongside `check_header_size_bit` /
//! `check_resolvable_methods` / `check_sigma_prop_root`) must flip with them.
//!
//! Every verdict here is the JVM oracle's verbatim output (sigma-state 6.0.2 +
//! ergo-core 6.0.2, `scripts/jvm_serde_oracle/ErgoSerdeOracle.scala` with the
//! `<surface>@<activated>` spec), pinned in
//! `test-vectors/scala/tree_version_activated_oracle.json`. It includes mainnet
//! block 545,684's tx[1] and its output[0] (`cd07021a8e6f59fd4a`, header
//! version 5) — accepted at activated 1 (the block's era), rejected at 2 and 3.

use ergo_primitives::cost::CostAccumulator;
use ergo_primitives::reader::VlqReader;
use ergo_primitives::writer::VlqWriter;
use ergo_ser::ergo_tree::{
    check_header_size_bit, check_resolvable_methods, check_sigma_prop_root,
    check_tree_version_supported, read_ergo_tree,
};
use ergo_sigma::evaluator::{reduce_expr_with_cost, validate_group_element, ReductionContext};
use ergo_sigma::reduce::verify_spending_proof_with_context;
use serde::Deserialize;

#[derive(Deserialize)]
struct OracleFile {
    vectors: Vec<OracleVector>,
}

#[derive(Deserialize)]
struct OracleVector {
    surface: String,
    activated_version: u8,
    hex: String,
    oracle: String,
    note: String,
    /// Set on a line where the node's verdict is a KNOWN, documented
    /// divergence from the JVM on this bare surface; the test pins the gap
    /// (node rejects, JVM accepts) instead of asserting parity.
    #[serde(default)]
    node_known_gap: Option<String>,
}

fn load_vectors() -> Vec<OracleVector> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("test-vectors/scala/tree_version_activated_oracle.json");
    let raw =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let file: OracleFile =
        serde_json::from_str(&raw).unwrap_or_else(|e| panic!("parse {}: {e}", path.display()));
    file.vectors
}

/// The node's verdict on the `ergo_tree` surface: parse, apply the box-script
/// gates under `activated`, and curve-check forwarded group elements.
/// `Some(canonical_hex)` = accepted.
fn tree_verdict(bytes: &[u8], activated: u8) -> Option<String> {
    let mut r = VlqReader::new(bytes).with_activated_script_version(activated);
    let tree = read_ergo_tree(&mut r).ok()?;
    check_tree_version_supported(&tree, activated).ok()?;
    check_header_size_bit(&tree).ok()?;
    check_resolvable_methods(&tree).ok()?;
    check_sigma_prop_root(&tree).ok()?;
    if !r
        .take_group_elements()
        .iter()
        .all(|ge| validate_group_element(*ge).is_ok())
    {
        return None;
    }
    let mut w = VlqWriter::new();
    ergo_ser::ergo_tree::write_ergo_tree(&mut w, &tree).ok()?;
    Some(hex::encode(w.result()))
}

/// The node's verdict on the `ergo_box_candidate` surface (standalone box,
/// full token ids): the consensus box reader scoped to `activated`, exactly as
/// a transaction-level parse under `VersionContext.withVersions(activated, …)`.
fn box_verdict(bytes: &[u8], activated: u8) -> Option<String> {
    let mut r = VlqReader::new(bytes).with_activated_script_version(activated);
    let candidate = ergo_ser::ergo_box::read_ergo_box_candidate(&mut r).ok()?;
    let mut w = VlqWriter::new();
    ergo_ser::ergo_box::write_ergo_box_candidate(&mut w, &candidate).ok()?;
    Some(hex::encode(w.result()))
}

/// The node's verdict on the `transaction` surface under `activated`.
fn tx_verdict(bytes: &[u8], activated: u8) -> Option<String> {
    let mut r = VlqReader::new(bytes).with_activated_script_version(activated);
    let tx = ergo_ser::transaction::read_transaction(&mut r).ok()?;
    let mut w = VlqWriter::new();
    ergo_ser::transaction::write_transaction(&mut w, &tx).ok()?;
    Some(hex::encode(w.result()))
}

fn minimal_ctx(tree: &ergo_ser::ergo_tree::ErgoTree, activated: u8) -> ReductionContext<'static> {
    ReductionContext {
        activated_script_version: activated,
        ergo_tree_version: tree.version,
        ..ReductionContext::minimal(0, 0)
    }
}

/// The node's verdict on the `reduce` surface: deserialize under `activated`
/// (box-script gates included) and reduce the root in a minimal context.
/// `Some("P:<sigma-boolean-hex>")` = reduced (the JVM line also carries `|cost`,
/// which the difftest `reduce` surface diffs; here only the proposition is
/// compared).
fn reduce_verdict(bytes: &[u8], activated: u8) -> Option<String> {
    let mut r = VlqReader::new(bytes).with_activated_script_version(activated);
    let tree = read_ergo_tree(&mut r).ok()?;
    check_tree_version_supported(&tree, activated).ok()?;
    check_header_size_bit(&tree).ok()?;
    check_resolvable_methods(&tree).ok()?;
    check_sigma_prop_root(&tree).ok()?;
    let ctx = minimal_ctx(&tree, activated);
    let mut cost = CostAccumulator::recording_only();
    let sb = reduce_expr_with_cost(&tree.body, &ctx, &tree.constants, &mut cost).ok()?;
    let mut w = VlqWriter::new();
    ergo_ser::sigma_value::write_sigma_boolean(&mut w, &sb).ok()?;
    Some(format!("P:{}", hex::encode(w.result())))
}

/// The node's verdict on the `verify` surface — the SPEND path: the tree is
/// read the way a stored box is (default context, activated 1), then
/// `verify_spending_proof_with_context` runs at `activated` with an empty proof
/// and message, where `check_soft_fork_condition` (Scala
/// `Interpreter.checkSoftForkCondition`, `Interpreter.scala:325-328`) refuses
/// a tree whose header version exceeds the activated version BEFORE any
/// reduction. `Some(true)` = the spend verifies.
fn verify_verdict(bytes: &[u8], activated: u8) -> Option<bool> {
    let mut r = VlqReader::new(bytes)
        .with_activated_script_version(ergo_ser::ergo_tree::DEFAULT_ACTIVATED_SCRIPT_VERSION);
    let tree = read_ergo_tree(&mut r).ok()?;
    let ctx = minimal_ctx(&tree, activated);
    verify_spending_proof_with_context(&tree, &[], &[], &ctx).ok()
}

// ----- oracle parity -----

#[test]
fn tree_version_gate_matches_the_jvm_at_every_activated_version() {
    let vectors = load_vectors();
    assert!(
        vectors.len() >= 52,
        "vector file must carry the full oracle runs"
    );
    let mut checked = 0;
    for v in &vectors {
        let bytes = hex::decode(&v.hex).unwrap();
        let jvm_accepts = v.oracle.starts_with("ACCEPT");
        let ours = match v.surface.as_str() {
            "ergo_tree" => tree_verdict(&bytes, v.activated_version),
            "ergo_box_candidate" => box_verdict(&bytes, v.activated_version),
            "transaction" => tx_verdict(&bytes, v.activated_version),
            "reduce" => {
                let ours = reduce_verdict(&bytes, v.activated_version);
                if let Some(gap) = &v.node_known_gap {
                    // Pinned gap: the JVM reduces, the node cannot — and the
                    // matching `verify` line must reject on both sides, which
                    // is what makes the gap unreachable on the spend path.
                    assert!(jvm_accepts, "known-gap line must be a JVM ACCEPT: {gap}");
                    assert!(
                        ours.is_none(),
                        "{}@{} {}: gap closed? update the vector ({gap})",
                        v.surface,
                        v.activated_version,
                        v.hex
                    );
                    let twin = vectors
                        .iter()
                        .find(|t| {
                            t.surface == "verify"
                                && t.activated_version == v.activated_version
                                && t.hex == v.hex
                        })
                        .expect("a known reduce gap needs its verify twin pinned");
                    assert!(twin.oracle.starts_with("REJECT"));
                    checked += 1;
                    continue;
                }
                // Compare the proposition; the JVM line carries `|<cost>`
                // after it, which the difftest `reduce` surface diffs.
                ours
            }
            "verify" => {
                let ours = verify_verdict(&bytes, v.activated_version);
                assert_eq!(
                    ours,
                    if jvm_accepts { Some(true) } else { None },
                    "verify@{} {}: JVM said `{}`, node said {:?} ({})",
                    v.activated_version,
                    v.hex,
                    v.oracle,
                    ours,
                    v.note
                );
                checked += 1;
                continue;
            }
            // `mc_root` lines document the JVM's rule-1001 wrap classification.
            _ => continue,
        };
        assert_eq!(
            ours.is_some(),
            jvm_accepts,
            "{}@{} {}: JVM said `{}`, node said {:?} ({})",
            v.surface,
            v.activated_version,
            v.hex,
            v.oracle,
            ours,
            v.note
        );
        if let (Some(canonical), Some(jvm_canonical)) =
            (ours.as_deref(), v.oracle.strip_prefix("ACCEPT "))
        {
            let jvm_canonical = jvm_canonical.split('|').next().unwrap();
            assert_eq!(
                canonical, jvm_canonical,
                "{}@{} {}: canonical form differs from the JVM",
                v.surface, v.activated_version, v.hex
            );
        }
        checked += 1;
    }
    assert!(checked >= 50, "checked only {checked} vectors");
}

/// The four cases of the reference rule, pinned by name so a CI line says which
/// one broke: inert below activated 2; `tree <= activated` accepted; `tree >
/// activated` rejected from activated 2 on (v3 at 2 included — the threshold is
/// the activated version, not a static maximum); sizeless `version != 0` is rule
/// 1012 regardless.
#[test]
fn tree_version_gate_four_cases_match_the_jvm() {
    let vectors = load_vectors();
    let jvm = |surface: &str, activated: u8, hex: &str| -> bool {
        vectors
            .iter()
            .find(|v| v.surface == surface && v.activated_version == activated && v.hex == hex)
            .unwrap_or_else(|| panic!("missing oracle vector {surface}@{activated} {hex}"))
            .oracle
            .starts_with("ACCEPT")
    };
    // 1. activated < 2: inert — v5 (and v7) parse at 0 and 1.
    assert!(jvm("ergo_tree", 0, "0d0208d3"));
    assert!(jvm("ergo_tree", 1, "0d0208d3"));
    assert!(jvm("ergo_tree", 1, "0f0208d3"));
    assert!(jvm("ergo_tree", 1, "cd07021a8e6f59fd4a"));
    // 2. activated >= 2, tree <= activated: accepted.
    assert!(jvm("ergo_tree", 2, "0a0208d3"));
    assert!(jvm("ergo_tree", 3, "0b0208d3"));
    // 3. activated >= 2, tree > activated: rejected, even by one.
    assert!(!jvm("ergo_tree", 2, "0b0208d3"));
    assert!(!jvm("ergo_tree", 3, "0c0208d3"));
    assert!(!jvm("ergo_tree", 2, "cd07021a8e6f59fd4a"));
    assert!(!jvm("ergo_tree", 3, "cd07021a8e6f59fd4a"));
    // 4. sizeless version != 0: rule 1012, at every activated version.
    assert!(!jvm("ergo_tree", 1, "0501d3"));
    assert!(!jvm("ergo_tree", 3, "0501d3"));
    // Spend-time twin (`Interpreter.checkSoftForkCondition`): a v3 tree box,
    // creatable under activated 0/1 (case 1), cannot be script-spent at
    // activated 2 (mainnet header-version-3 era) but can at 3; a v5 tree can
    // never be script-spent below activated 2.
    assert!(!jvm("verify", 2, "0b0208d3"));
    assert!(jvm("verify", 3, "0b0208d3"));
    assert!(jvm("verify", 2, "0a0208d3"));
    assert!(!jvm("verify", 1, "0d0208d3"));
    assert!(!jvm("verify", 1, "cd07021a8e6f59fd4a"));
    // And the node agrees on each (the parity test above covers every line;
    // this spells the rule out).
    for (activated, hex, accept) in [
        (0u8, "0d0208d3", true),
        (1, "0d0208d3", true),
        (2, "0a0208d3", true),
        (2, "0b0208d3", false),
        (3, "0b0208d3", true),
        (3, "0c0208d3", false),
        (1, "0501d3", false),
        (3, "0501d3", false),
    ] {
        assert_eq!(
            tree_verdict(&hex::decode(hex).unwrap(), activated).is_some(),
            accept,
            "{hex} at activated {activated}"
        );
    }
}
