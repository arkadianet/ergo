//! ErgoTree assembly + the public end-to-end [`compile`] API (M3 Task 9).
//!
//! Wires the full pipeline source → bytes → address: parse → bind →
//! typecheck ([`crate::typecheck_with_network`]) → root coercion → emit
//! ([`crate::emit`]) → [`build_tree`] → wire write → P2S/P2SH address
//! construction. Mirrors the node's compile surface,
//! `ScriptApiRoute.compileSource`
//! (`ergo/src/main/scala/org/ergoplatform/http/api/ScriptApiRoute.scala:56-67`).

use ergo_primitives::writer::VlqWriter;
use ergo_ser::address::{encode_p2s, encode_p2sh, NetworkPrefix};
use ergo_ser::ergo_tree::{write_ergo_tree, ErgoTree};
use ergo_ser::opcode::{write_expr, Expr, IrNode, Payload};

use crate::emit::emit;
use crate::env::ScriptEnv;
use crate::stype::SType;
use crate::typecheck::{typecheck_with_network, CompileError};
use crate::typed::node_tpe;
use crate::typed_print::to_term_string;

/// The output of a successful [`compile`]: the assembled tree, its wire
/// bytes, and both script-address encodings.
#[derive(Debug, Clone, PartialEq)]
pub struct CompileResult {
    /// Canonical wire bytes of `ergo_tree` (`write_ergo_tree` output).
    pub tree_bytes: Vec<u8>,
    /// The assembled tree (M3: always version 0, non-segregated, no size).
    pub ergo_tree: ErgoTree,
    /// Pay-to-Script address over the FULL `tree_bytes`
    /// (`ergo_ser::address::encode_p2s`). Deliberately NOT routed through
    /// `encode_address`/`encode_address_from_tree_bytes`: the compile surface
    /// always answers P2S (Scala `Pay2SAddress(tree)`), even when the tree is
    /// a bare `SigmaPropConstant(ProveDlog)` that the wallet-side
    /// `fromProposition` routing would render as P2PK.
    pub p2s_address: String,
    /// Pay-to-Script-Hash address over the PROPOSITION bytes (root
    /// expression only, no tree header/constants wrapper) — Scala
    /// `Pay2SHAddress(prop)`, `ErgoAddress.scala:201-218`.
    pub p2sh_address: String,
}

/// Assemble the M3 ErgoTree around an emitted root expression.
///
/// Mirrors `ErgoTree.fromProposition(header, prop)` (sigma-state 6.0.2,
/// `core/.../sigma/ast/ErgoTree.scala:344-349`):
///
/// ```text
/// prop match {
///   case SigmaPropConstant(_) => withoutSegregation(header, prop)   // header 0x00
///   case _                    => withSegregation(header, prop)      // header 0x10
/// }
/// ```
///
/// At M3 we implement ONLY the `withoutSegregation` branch for EVERY root —
/// header `0x00`, empty constants table, inline constants in the body. For a
/// bare-constant root (e.g. `PK("...")` → `SigmaPropConstant`) this is
/// byte-identical to Scala; for any other root Scala segregates (header
/// `0x10`, constants pulled into the table, `ConstPlaceholder` in the body) —
/// THAT is the M4 flip point (the constant-segregation transform), tracked in
/// the module ledger. Both forms are valid, parseable, semantically equal
/// trees; only the bytes (and hence the P2S address) differ.
///
/// Header provenance (route fact): the wire header always comes from
/// `ErgoTree.defaultHeaderWithVersion(0)` — `ScriptApiRoute.compileSource`
/// never forwards its `treeVersion` request parameter into the header; that
/// parameter only gates frontend method visibility via
/// `VersionContext.withVersions`. So `version` is fixed 0 and `has_size`
/// false (the size bit is only required for version > 0).
pub(crate) fn build_tree(root: Expr) -> ErgoTree {
    ErgoTree {
        version: 0,
        has_size: false,
        constant_segregation: false,
        constants: vec![],
        body: root,
    }
}

/// Compile ErgoScript `source` end-to-end: typecheck, lower to opcode IR,
/// assemble the ErgoTree, serialize, and derive the P2S/P2SH addresses.
///
/// Pipeline: parse → bind → typecheck → root-coerce → emit → [`build_tree`] →
/// `write_ergo_tree` → addresses. Mirrors `ScriptApiRoute.compileSource`
/// (`ScriptApiRoute.scala:56-67`).
///
/// # The three version axes
///
/// 1. **`tree_version` (axis 1, frontend gate ONLY):** threads the v5/v6
///    method-table + predef visibility gate through parse/bind/typecheck
///    (`tree_version >= 3` ⇔ `VersionContext.isV3OrLaterErgoTreeVersion`).
///    Scala's route forwards its `treeVersion` param ONLY into
///    `VersionContext.withVersions` — never into the tree header.
/// 2. **Wire header version (axis 2):** fixed at 0 in M3 (and in the route:
///    `ErgoTree.defaultHeaderWithVersion(0.toByte)` unconditionally). See
///    [`build_tree`].
/// 3. **Activated script version (axis 3):** the EVALUATOR's
///    block-consensus version; a compile-time no-op here — it decides how a
///    node executes the tree, not what bytes we produce.
///
/// # Root coercion
///
/// Mirrors the route's dispatch (`ScriptApiRoute.scala:60-65`): a
/// `SigmaProp`-typed root passes through; a `Boolean`-typed root is wrapped
/// in `BoolToSigmaProp` (opcode `0xD1`, Scala `script.toSigmaProp`); any
/// other root type is [`CompileError::Root`] (the route's bare
/// `new Exception(...)`; oracle: `cc HEIGHT` → `REJECT 0:0 Exception`).
///
/// # P2SH contract
///
/// The P2SH content hash covers the PROPOSITION bytes — the serialized root
/// expression WITHOUT the ErgoTree header/constants wrapper
/// (`Pay2SHAddress.apply(prop)`, `ErgoAddress.scala:210-218`). At M3 trees
/// are non-segregated, so the body already has every constant inline and no
/// substitution step is needed. M4 NOTE: once [`build_tree`] grows the
/// segregation branch, the proposition must be constant-INLINED first
/// (`toProposition(replaceConstants = isConstantSegregation)`,
/// `Pay2SHAddress.apply(script: ErgoTree)`, `ErgoAddress.scala:201-204`) —
/// hashing a body with `ConstPlaceholder` nodes yields a wrong address.
///
/// # Known accept-side residual (Task-10 gate input)
///
/// Postfix method-call residuals the typer accepts (e.g. `coll size` typed as
/// a residual `MethodCall`) emit successfully here, while Scala's FULL
/// compiler (`compile`, not `typecheck`) throws at the later GraphBuilding
/// stage. We deliberately do NOT pre-reject such shapes in `compile()` —
/// Task 10's oracle verdict gate adjudicates each divergence.
///
/// # Examples
///
/// ```
/// use ergo_compiler::{compile, NetworkPrefix, ScriptEnv};
///
/// let r = compile(&ScriptEnv::new(), "sigmaProp(HEIGHT > 100)", 0, NetworkPrefix::Mainnet)
///     .unwrap();
/// // M3 trees are non-segregated: header byte 0x00.
/// assert_eq!(r.tree_bytes[0], 0x00);
/// ```
pub fn compile(
    env: &ScriptEnv,
    source: &str,
    tree_version: u8,
    network: NetworkPrefix,
) -> Result<CompileResult, CompileError> {
    let typed = typecheck_with_network(env, source, tree_version, network)?;

    // Root dispatch — ScriptApiRoute.scala:60-65.
    let root = match node_tpe(&typed) {
        SType::SSigmaProp => emit(&typed)?,
        SType::SBoolean => Expr::Op(IrNode {
            // BoolToSigmaProp — Scala `script.toSigmaProp` (values.scala:58).
            opcode: 0xD1,
            payload: Payload::One(Box::new(emit(&typed)?)),
        }),
        other => {
            return Err(CompileError::Root {
                tpe: to_term_string(other),
            })
        }
    };

    let ergo_tree = build_tree(root);

    let mut w = VlqWriter::new();
    write_ergo_tree(&mut w, &ergo_tree)?;
    let tree_bytes = w.result();

    // Proposition bytes for P2SH: root expression only, no header/constants.
    // Non-segregated at M3, so no constant-inlining step (see the fn docs).
    let mut pw = VlqWriter::new();
    write_expr(&mut pw, &ergo_tree.body, false)?;
    let proposition_bytes = pw.result();

    let p2s_address = encode_p2s(network, &tree_bytes);
    let p2sh_address = encode_p2sh(network, &proposition_bytes);

    Ok(CompileResult {
        tree_bytes,
        ergo_tree,
        p2s_address,
        p2sh_address,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::env::EnvValue;
    use ergo_primitives::group_element::GroupElement;
    use ergo_primitives::reader::VlqReader;
    use ergo_ser::ergo_tree::read_ergo_tree;
    use ergo_ser::sigma_type::SigmaType;
    use ergo_ser::sigma_value::{SigmaBoolean, SigmaValue};

    // ----- helpers -----

    /// secp256k1 generator, SEC1-compressed. The Task-1 PK test address
    /// `3WwXpssaZwcNzaGMv3AgxBdTPJQBt5gCmqBsg3DykQ39bYdhJBsN` decodes to
    /// ProveDlog of exactly this point (the well-known "secret = 1" testnet
    /// address), and the oracle env's `g1` is bound to it too.
    const GENERATOR_HEX: &str =
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

    /// Oracle capture, VERBATIM (TyperOracle.scala `cc` verb, sigma-state
    /// 6.0.2 SigmaCompiler + ErgoTreeSerializer + Pay2S/Pay2SHAddress,
    /// ORACLE_NETWORK=testnet, captured 2026-07-04,
    /// `.superpowers/sdd/task-1-report.md` Step-4 smoke, line 2):
    ///
    ///   cc PK("3WwXpssaZwcNzaGMv3AgxBdTPJQBt5gCmqBsg3DykQ39bYdhJBsN")
    ///   → OK <ORACLE_PK_TREE_HEX> <ORACLE_PK_P2S> <ORACLE_PK_P2SH>
    const ORACLE_PK_TREE_HEX: &str =
        "0008cd0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    const ORACLE_PK_P2S: &str = "5AgXz2KadZrAXE86MMjVQ7UAWeRFbhBZcQms4j2RgBuHNrVRwY7xvp2S";
    const ORACLE_PK_P2SH: &str = "qETVgcEctaXurNbFRgGUcZEGg4EKa8R4a5UNHY7";

    /// Same capture, line 1:
    ///
    ///   cc sigmaProp(HEIGHT > 100)
    ///   → OK 100104c801d191a37300 Xw4DF8oEhUcUi3f7LAHt
    ///        qT5wgrLU3mrxjSQ8FLdaxK3TYcHcHsSLizxPe4S
    ///
    /// The oracle tree is SEGREGATED (header 0x10, constants table
    /// `01 04c801`, body `d191a37300` with placeholder `7300`); its
    /// constant-INLINED proposition — what Pay2SHAddress hashes — is
    /// `d191a304c801`.
    const ORACLE_HGT_P2S: &str = "Xw4DF8oEhUcUi3f7LAHt";
    const ORACLE_HGT_P2SH: &str = "qT5wgrLU3mrxjSQ8FLdaxK3TYcHcHsSLizxPe4S";

    fn compile_testnet(env: &ScriptEnv, source: &str) -> Result<CompileResult, CompileError> {
        // tree_version 0 = the route default; axis-1 only gates v6 method
        // visibility, which none of these sources touch.
        compile(env, source, 0, NetworkPrefix::Testnet)
    }

    fn ct(source: &str) -> Result<CompileResult, CompileError> {
        compile_testnet(&ScriptEnv::new(), source)
    }

    fn generator_env() -> ScriptEnv {
        let bytes: [u8; 33] = hex::decode(GENERATOR_HEX).unwrap().try_into().unwrap();
        let mut env = ScriptEnv::new();
        env.insert(
            "g1",
            EnvValue::GroupElement(GroupElement::from_bytes(bytes)),
        );
        env
    }

    fn reparse(bytes: &[u8]) -> ErgoTree {
        let mut r = VlqReader::new(bytes);
        read_ergo_tree(&mut r).expect("compiled tree must reparse")
    }

    // ----- happy path -----

    #[test]
    fn compile_bool_root_wraps_in_bool_to_sigma_prop() {
        // `HEIGHT > 100` types SBoolean → route coercion wraps in 0xD1
        // (ScriptApiRoute.scala:62-63 `script.toSigmaProp`), producing the
        // SAME tree as the explicit `sigmaProp(...)` form.
        let bare = ct("HEIGHT > 100").expect("compile");
        let explicit = ct("sigmaProp(HEIGHT > 100)").expect("compile");
        assert!(
            matches!(&bare.ergo_tree.body, Expr::Op(IrNode { opcode: 0xD1, .. })),
            "bool root must be wrapped in BoolToSigmaProp"
        );
        assert_eq!(bare.tree_bytes, explicit.tree_bytes);
        assert_eq!(bare.p2s_address, explicit.p2s_address);
        assert_eq!(bare.p2sh_address, explicit.p2sh_address);
    }

    #[test]
    fn compile_pk_bare_const_header_zero_and_shape() {
        // PK(...) compiles straight to a bare SigmaPropConstant — the
        // fromProposition `SigmaPropConstant(_)` branch (withoutSegregation):
        // header 0x00, empty constants, body = the constant itself (the
        // exact `detect_p2pk` shape in ergo-ser).
        let r = compile_testnet(
            &ScriptEnv::new(),
            r#"PK("3WwXpssaZwcNzaGMv3AgxBdTPJQBt5gCmqBsg3DykQ39bYdhJBsN")"#,
        )
        .expect("compile");
        assert_eq!(r.tree_bytes[0], 0x00, "non-segregated v0 header");
        assert!(r.ergo_tree.constants.is_empty());
        assert!(matches!(
            &r.ergo_tree.body,
            Expr::Const {
                tpe: SigmaType::SSigmaProp,
                val: SigmaValue::SigmaProp(SigmaBoolean::ProveDlog(_)),
            }
        ));
    }

    #[test]
    fn compile_sigmaprop_height_header_zero_nonsegregated() {
        // Decision 3 (M3): EVERY tree is emitted non-segregated (header
        // 0x00). Scala segregates non-bare-constant roots (header 0x10, see
        // the oracle capture in the parity section) — the M4 flip point is
        // build_tree's missing withSegregation branch.
        let r = ct("sigmaProp(HEIGHT > 100)").expect("compile");
        assert_eq!(r.tree_bytes[0], 0x00);
        assert!(!r.ergo_tree.constant_segregation);
        assert!(r.ergo_tree.constants.is_empty());
        // Oracle-derived expected bytes: 0x00 header + the constant-inlined
        // proposition of the oracle capture (`100104c801d191a37300` with
        // placeholder 7300 → constant 04c801) = 00 d1 91 a3 04c801.
        assert_eq!(hex::encode(&r.tree_bytes), "00d191a304c801");
    }

    // ----- round-trips -----

    #[test]
    fn compile_output_reparses_to_same_tree() {
        for src in [
            r#"PK("3WwXpssaZwcNzaGMv3AgxBdTPJQBt5gCmqBsg3DykQ39bYdhJBsN")"#,
            "sigmaProp(HEIGHT > 100)",
            "HEIGHT > 100",
        ] {
            let r = compile_testnet(&ScriptEnv::new(), src).expect("compile");
            assert_eq!(reparse(&r.tree_bytes), r.ergo_tree, "src = {src}");
        }
        let r = compile_testnet(&generator_env(), "proveDlog(g1)").expect("compile");
        assert_eq!(reparse(&r.tree_bytes), r.ergo_tree);
    }

    // ----- error paths -----

    #[test]
    fn compile_int_root_rejects_with_exception_class() {
        // Route :64-65: neither Bool nor SigmaProp root → bare Exception.
        let err = ct("1 + 1").expect_err("Int root must reject");
        assert!(matches!(&err, CompileError::Root { tpe } if tpe == "Int"));
        assert_eq!(err.class(), "Exception");
        assert_eq!(err.pos(), 0);
    }

    #[test]
    fn compile_height_root_rejects_matching_oracle_probe() {
        // Oracle (task-1-report.md extra probes): `cc HEIGHT` →
        // `REJECT 0:0 Exception`.
        let err = ct("HEIGHT").expect_err("Int root must reject");
        assert_eq!(err.class(), "Exception");
        assert_eq!(err.pos(), 0);
    }

    #[test]
    fn compile_parse_error_propagates_as_parse_phase() {
        let err = ct(")(").expect_err("parse must fail");
        assert!(matches!(err, CompileError::Parse(_)));
    }

    // ----- oracle parity -----

    #[test]
    fn compile_pk_bytes_and_addresses_match_oracle() {
        // The ONE byte-gated class at M3: a bare-constant root takes the
        // withoutSegregation branch on BOTH sides, so bytes AND both
        // addresses must match the oracle verbatim (capture provenance on
        // the ORACLE_PK_* consts above; testnet capture → testnet compile).
        let r = compile_testnet(
            &ScriptEnv::new(),
            r#"PK("3WwXpssaZwcNzaGMv3AgxBdTPJQBt5gCmqBsg3DykQ39bYdhJBsN")"#,
        )
        .expect("compile");
        assert_eq!(hex::encode(&r.tree_bytes), ORACLE_PK_TREE_HEX);
        assert_eq!(r.p2s_address, ORACLE_PK_P2S);
        assert_eq!(r.p2sh_address, ORACLE_PK_P2SH);
        // The oracle P2S reply doubles as the forced-P2S pin: Scala's
        // Pay2SAddress answers P2S even for a bare ProveDlog constant, and
        // matching it proves we did not route through encode_address (which
        // would detect_p2pk this exact body and emit a P2PK address).
        // Belt-and-braces: the raw prefix byte is testnet|P2S = 0x13.
        let raw = bs58::decode(&r.p2s_address).into_vec().unwrap();
        assert_eq!(raw[0], 0x13, "testnet P2S prefix, not P2PK (0x11)");
    }

    #[test]
    fn compile_sigmaprop_height_p2s_differs_p2sh_matches_oracle() {
        // Honest M3 state for the segregated class: the oracle tree is
        // `100104c801d191a37300` (header 0x10); ours is non-segregated
        // (header 0x00, asserted in the happy-path section), so the tree
        // bytes and the P2S address MUST differ until the M4 segregation
        // transform lands. The semantic-equality gate is Task 10.
        let r = ct("sigmaProp(HEIGHT > 100)").expect("compile");
        assert_ne!(r.p2s_address, ORACLE_HGT_P2S);
        // The P2SH address, however, hashes the constant-INLINED proposition
        // (`d191a304c801`) — exactly our non-segregated body bytes — so it
        // must MATCH the oracle capture byte-for-byte. This is a genuine
        // cross-representation parity gate on our proposition bytes.
        assert_eq!(r.p2sh_address, ORACLE_HGT_P2SH);
    }

    #[test]
    fn compile_prove_dlog_generator_unfolded_header_and_shape_only() {
        // Oracle capture, line 3: `cce proveDlog(g1)` → the SAME reply as
        // the PK line (tree `0008cd0279be...`, both addresses identical):
        // Scala's IR pipeline constant-folds CreateProveDlog(const) →
        // SigmaPropConstant at the GraphBuilding stage (task-1-report.md
        // Concern 1; g1 = the generator = the PK test key). WE emit the
        // unfolded `CreateProveDlog(Const)` — still non-segregated 0x00 but
        // DIFFERENT body bytes, so this asserts header/shape only. The
        // constant fold is an M4/M5 lowering rule (ledger note).
        let r = compile_testnet(&generator_env(), "proveDlog(g1)").expect("compile");
        assert_eq!(r.tree_bytes[0], 0x00);
        assert!(r.ergo_tree.constants.is_empty());
        // Body = CreateProveDlog (0xCD) over a GroupElement constant.
        match &r.ergo_tree.body {
            Expr::Op(IrNode {
                opcode: 0xCD,
                payload: Payload::One(inner),
            }) => assert!(matches!(
                inner.as_ref(),
                Expr::Const {
                    tpe: SigmaType::SGroupElement,
                    ..
                }
            )),
            other => panic!("expected CreateProveDlog node, got {other:?}"),
        }
        // NOT byte-equal to the oracle's folded bare-constant tree.
        assert_ne!(hex::encode(&r.tree_bytes), ORACLE_PK_TREE_HEX);
        assert_ne!(r.p2s_address, ORACLE_PK_P2S);
        assert_ne!(r.p2sh_address, ORACLE_PK_P2SH);
    }
}
