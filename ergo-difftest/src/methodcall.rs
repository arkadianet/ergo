//! MethodCall typechecker-registry verification harness.
//!
//! The Phase-3 root typechecker (rule 1001) must decide, for a `MethodCall` /
//! `PropertyCall`-rooted ErgoTree, whether the method's result static type is
//! `SigmaProp`. Getting that classification wrong for a method that CAN return
//! `SigmaProp` would reject a Scala-accepted tree (a consensus reject-valid), and
//! the differential campaign barely exercises MethodCall roots. This harness
//! machine-verifies every `(type_id, method_id)` against the JVM reference BEFORE
//! the registry ships:
//!
//!  - it constructs a `MethodCall`-root tree for each method, programmatically via
//!    the node's own ergo-ser writer (no fragile hand-hex), classifies its root BOTH
//!    with the node's rule-1001 typer (`read_ergo_tree` + `determinable_root_type_of`)
//!    AND the oracle's `mc_root` surface, and DIFFS them. The oracle answers `SIGMA`
//!    (root IS `SigmaProp`), `WRAP` (wrapped by rule 1001 — the MethodCall reached
//!    the root classification and its result is non-`SigmaProp`), `WRAPOTHER`
//!    (wrapped for another reason, e.g. method-not-found — the probe never reached
//!    rule 1001), or `THROW`; the node answers `SIGMA` / `WRAP` / `LENIENT` (root
//!    type not statically determinable — the safe, never-reject direction) /
//!    `THROW`. A probe passes iff the oracle matched the pass's expectation AND the
//!    node's verdict is reject-valid-safe against it (it never `WRAP`s a tree the
//!    oracle accepts as `SigmaProp`). This is the end-to-end Phase-3 verification;
//!  - the **SELF pass** gives every method a receiver of the wrong type (`SELF`, a
//!    `Box`). Scala's `specializeFor` degrades to the unspecialized template, whose
//!    result is never `SigmaProp`, so EVERY method must answer `WRAP`. This proves
//!    no method is UNCONDITIONALLY `SigmaProp`. A `THROW` FAILS the pass (the probe
//!    never reached the rule-1001 classification, so it proves nothing) — every
//!    probe must be a valid tree;
//!  - the **landmine pass** gives the 7 methods whose result is a bare type variable
//!    a `SigmaProp`-instantiated receiver/arg, and asserts each answers `SIGMA`.
//!    These are exactly the methods the registry must treat as `SigmaProp`-capable
//!    (a Coll/Option element projection, a fold accumulator, or an explicit type
//!    arg) — every other method's result is a concrete type or an
//!    `Option`/`Coll`/tuple wrapper that is structurally never `SigmaProp`.
//!
//! Ground truth for the method set is `test-vectors/scala/sigma/method_result_types.tsv`,
//! produced by `scripts/jvm_serde_oracle/MethodDump.scala` from Scala's `SMethod`
//! registry (sigma-state 6.0.2).

use crate::oracle::Oracle;
use ergo_primitives::writer::VlqWriter;
use ergo_ser::ergo_tree::{write_ergo_tree, ErgoTree};
use ergo_ser::opcode::{Expr, IrNode, Payload};
use ergo_ser::sigma_type::SigmaType;
use ergo_ser::sigma_value::{CollValue, SigmaBoolean, SigmaValue};

/// The checked-in method registry (one TSV row per `(type_id, method_id)`).
const METHOD_TSV: &str = include_str!("../../test-vectors/scala/sigma/method_result_types.tsv");

// ----- IR constructors -----

fn op(opcode: u8, payload: Payload) -> Expr {
    Expr::Op(IrNode { opcode, payload })
}

/// `SELF` — a `Box`-typed leaf, the universal wrong-type receiver.
fn self_box() -> Expr {
    op(0xA7, Payload::Zero)
}

/// `Global` — the `SGlobal` receiver leaf.
fn global() -> Expr {
    op(0xDD, Payload::Zero)
}

fn int_const(v: i32) -> Expr {
    Expr::Const {
        tpe: SigmaType::SInt,
        val: SigmaValue::Int(v),
    }
}

fn sigma_prop_const() -> Expr {
    Expr::Const {
        tpe: SigmaType::SSigmaProp,
        val: SigmaValue::SigmaProp(SigmaBoolean::TrivialProp(true)),
    }
}

/// An empty `Coll[Byte]` constant — a valid `bytes` argument.
fn byte_coll_const() -> Expr {
    Expr::Const {
        tpe: SigmaType::SColl(Box::new(SigmaType::SByte)),
        val: SigmaValue::Coll(CollValue::Bytes(vec![])),
    }
}

/// `Coll[SigmaProp]` literal `[sigmaProp(true)]`.
fn coll_sigma_prop() -> Expr {
    op(
        0x83,
        Payload::ConcreteCollection {
            elem_type: SigmaType::SSigmaProp,
            items: vec![sigma_prop_const()],
        },
    )
}

/// `getVar[SigmaProp](0)` — statically `Option[SigmaProp]`.
fn option_sigma_prop() -> Expr {
    op(
        0xE3,
        Payload::GetVar {
            var_id: 0,
            tpe: SigmaType::SSigmaProp,
        },
    )
}

/// `(acc: SigmaProp, item: SigmaProp) => acc` — a valid fold op whose result type
/// is `SigmaProp`, so `Coll.fold` over it yields a `SigmaProp` accumulator.
fn fold_op_sigma_prop() -> Expr {
    op(
        0xD9,
        Payload::FuncValue {
            args: vec![
                (1, Some(SigmaType::SSigmaProp)),
                (2, Some(SigmaType::SSigmaProp)),
            ],
            body: Box::new(op(0x72, Payload::ValUse { id: 1 })),
        },
    )
}

// ----- tree assembly -----

/// Serialize a has_size v3 ErgoTree whose body is the given `MethodCall` /
/// `PropertyCall`. `PropertyCall` (0xDB) is used iff there are no value args.
fn build_tree(
    type_id: u8,
    method_id: u8,
    obj: Expr,
    args: Vec<Expr>,
    type_args: Vec<SigmaType>,
) -> Vec<u8> {
    let opcode = if args.is_empty() { 0xDB } else { 0xDC };
    let body = op(
        opcode,
        Payload::MethodCall {
            type_id,
            method_id,
            obj: Box::new(obj),
            args,
            type_args,
        },
    );
    let tree = ErgoTree {
        version: 3,
        has_size: true,
        constant_segregation: false,
        constants: vec![],
        body,
    };
    let mut w = VlqWriter::new();
    write_ergo_tree(&mut w, &tree).expect("write methodcall tree");
    w.result()
}

// ----- method registry -----

/// One method from the registry TSV.
#[derive(Debug, Clone)]
pub struct Method {
    pub type_id: u8,
    pub method_id: u8,
    pub name: String,
    /// Result is or contains a type variable — only these can possibly specialize
    /// to `SigmaProp` (the 7 landmines do; the rest are `Option`/`Coll` wrappers).
    pub has_type_var: bool,
    pub arity: usize,
    pub n_type_args: usize,
}

/// The 7 `(type_id, method_id)` whose result is a bare type variable.
const LANDMINE_IDS: &[(u8, u8)] = &[
    (12, 10),
    (12, 2),
    (12, 5),
    (36, 3),
    (36, 4),
    (106, 4),
    (106, 5),
];

impl Method {
    pub fn is_landmine(&self) -> bool {
        LANDMINE_IDS.contains(&(self.type_id, self.method_id))
    }
}

/// Parse the embedded registry TSV (skips the header).
pub fn methods() -> Vec<Method> {
    METHOD_TSV
        .lines()
        .skip(1)
        .filter(|l| !l.trim().is_empty())
        .map(|line| {
            let c: Vec<&str> = line.split('\t').collect();
            Method {
                type_id: c[0].parse().expect("type_id"),
                method_id: c[1].parse().expect("method_id"),
                name: c[2].to_string(),
                has_type_var: c[5] == "true",
                arity: c[6].parse().expect("arity"),
                n_type_args: c[7].parse().expect("explicitTypeArgs"),
            }
        })
        .collect()
}

/// A `SigmaProp`-instantiated receiver for a method on `type_id`: a
/// `Coll[SigmaProp]` / `Option[SigmaProp]` so a Coll/Option element projection
/// resolves to `SigmaProp`. For every other receiver type the `SigmaProp` comes
/// from an explicit type arg (or the method is monomorphic), so `SELF` suffices.
fn sigma_receiver_for(type_id: u8) -> Expr {
    match type_id {
        12 => coll_sigma_prop(),
        36 => option_sigma_prop(),
        _ => self_box(),
    }
}

/// The 7 methods whose result is a bare type variable — the only ones that can
/// specialize to `SigmaProp`. Each entry builds a `SigmaProp`-yielding tree.
fn landmines() -> Vec<(u8, u8, &'static str, Vec<u8>)> {
    vec![
        // Coll[SigmaProp].apply(0): IV = SigmaProp
        (
            12,
            10,
            "Coll.apply",
            build_tree(12, 10, coll_sigma_prop(), vec![int_const(0)], vec![]),
        ),
        // Coll[SigmaProp].getOrElse(0, sigma): IV = SigmaProp
        (
            12,
            2,
            "Coll.getOrElse",
            build_tree(
                12,
                2,
                coll_sigma_prop(),
                vec![int_const(0), sigma_prop_const()],
                vec![],
            ),
        ),
        // Coll.fold(sigmaZero, (acc,item)=>acc): OV (accumulator) = SigmaProp
        (
            12,
            5,
            "Coll.fold",
            build_tree(
                12,
                5,
                coll_sigma_prop(),
                vec![sigma_prop_const(), fold_op_sigma_prop()],
                vec![],
            ),
        ),
        // Option[SigmaProp].get: T = SigmaProp  (property)
        (
            36,
            3,
            "Option.get",
            build_tree(36, 3, option_sigma_prop(), vec![], vec![]),
        ),
        // Option[SigmaProp].getOrElse(sigma): T = SigmaProp
        (
            36,
            4,
            "Option.getOrElse",
            build_tree(36, 4, option_sigma_prop(), vec![sigma_prop_const()], vec![]),
        ),
        // Global.deserializeTo[SigmaProp](bytes): T (explicit) = SigmaProp
        (
            106,
            4,
            "Global.deserializeTo",
            build_tree(
                106,
                4,
                global(),
                vec![byte_coll_const()],
                vec![SigmaType::SSigmaProp],
            ),
        ),
        // Global.fromBigEndianBytes[SigmaProp](bytes): T (explicit) = SigmaProp
        (
            106,
            5,
            "Global.fromBigEndianBytes",
            build_tree(
                106,
                5,
                global(),
                vec![byte_coll_const()],
                vec![SigmaType::SSigmaProp],
            ),
        ),
    ]
}

// ----- the scan -----

/// Outcome of one method probe.
#[derive(Debug, Clone, PartialEq)]
pub struct Probe {
    pub type_id: u8,
    pub method_id: u8,
    pub name: String,
    /// The oracle's `mc_root` answer (`SIGMA` / `WRAP` / `WRAPOTHER` / `THROW ...`).
    pub oracle: String,
    /// The node's own classification of the same tree (`SIGMA` / `WRAP` / `THROW`),
    /// via `read_ergo_tree` — the rule-1001 typer under test.
    pub rust: String,
    /// `true` iff the oracle matched the pass's expectation AND the node agrees with
    /// the oracle (the real differential check).
    pub ok: bool,
}

/// The node's rule-1001 classification of a has_size MethodCall-root tree, via the
/// SAME path the box reader uses (`read_ergo_tree` + `determinable_root_type_of`):
///   `SIGMA`   root statically typed `SigmaProp` (parses);
///   `WRAP`    root statically non-`SigmaProp` (soft-fork-wrapped → `Unparsed`);
///   `LENIENT` root type not statically determinable (parses — the safe direction,
///             can never reject a tree the JVM accepts);
///   `THROW`   the tree did not parse.
fn rust_verdict(bytes: &[u8]) -> &'static str {
    use ergo_primitives::reader::VlqReader;
    use ergo_ser::ergo_tree::{determinable_root_type_of, read_ergo_tree};
    use ergo_ser::sigma_type::SigmaType;
    let mut r = VlqReader::new(bytes);
    match read_ergo_tree(&mut r) {
        Ok(tree) => match &tree.body {
            Expr::Unparsed(_) => "WRAP",
            body => match determinable_root_type_of(body, &tree.constants) {
                Some(SigmaType::SSigmaProp) => "SIGMA",
                Some(_) => "WRAP",
                None => "LENIENT",
            },
        },
        Err(_) => "THROW",
    }
}

/// Build a probe: query the oracle, classify with the node, and pass iff the oracle
/// answered `expected_oracle` AND the node's verdict is in `allowed_rust`. The
/// reject-valid case (node `WRAP` while the oracle says `SIGMA`) is excluded from
/// every `allowed_rust` set, so it always fails. A `WRAPOTHER` oracle answer (a
/// non-rule-1001 wrap — the probe never reached the classification) fails
/// `expected_oracle`.
fn probe(
    oracle: &mut Oracle,
    type_id: u8,
    method_id: u8,
    name: &str,
    bytes: &[u8],
    expected_oracle: &str,
    allowed_rust: &[&str],
) -> std::io::Result<Probe> {
    let oracle_verdict = oracle.query_raw("mc_root", bytes)?;
    let rust = rust_verdict(bytes).to_string();
    Ok(Probe {
        type_id,
        method_id,
        name: name.to_string(),
        ok: oracle_verdict == expected_oracle && allowed_rust.contains(&rust.as_str()),
        oracle: oracle_verdict,
        rust,
    })
}

/// Result of a full scan.
pub struct Report {
    /// SELF pass — every method with a wrong-type receiver. A FAIL here is a
    /// method that answered `SIGMA` despite a non-`SigmaProp` receiver: a method
    /// that is unconditionally `SigmaProp`, which the dump says cannot exist.
    pub self_pass: Vec<Probe>,
    /// Landmine pass — the 7 type-variable methods with `SigmaProp` receivers; a
    /// FAIL is a method that did NOT answer `SIGMA` (mis-constructed or the dump's
    /// landmine set is wrong).
    pub landmine_pass: Vec<Probe>,
    /// Wrapper pass — every OTHER type-variable method, with its type variable
    /// instantiated to `SigmaProp` (a `Coll[SigmaProp]`/`Option[SigmaProp]` receiver
    /// or a `[SigmaProp]` explicit type). Each must answer non-`SIGMA`: a
    /// `Coll[SigmaProp]`/`Option[SigmaProp]` wrapper is structurally never
    /// `SigmaProp`. A FAIL is a polymorphic method that becomes `SigmaProp` but is
    /// NOT in the landmine set — i.e. the registry's landmine set is incomplete.
    pub wrapper_pass: Vec<Probe>,
}

impl Report {
    pub fn failures(&self) -> usize {
        self.self_pass.iter().filter(|p| !p.ok).count()
            + self.landmine_pass.iter().filter(|p| !p.ok).count()
            + self.wrapper_pass.iter().filter(|p| !p.ok).count()
    }
}

/// Run the full scan against the oracle.
pub fn run(oracle: &mut Oracle) -> std::io::Result<Report> {
    let methods = methods();

    // SELF pass: wrong-type receiver, dummy args. Expect WRAP for every one — a
    // THROW means the probe never reached the rule-1001 classification (see `probe`).
    let mut self_pass = Vec::with_capacity(methods.len());
    for m in &methods {
        let args: Vec<Expr> = (1..m.arity).map(|_| int_const(0)).collect();
        let type_args: Vec<SigmaType> = (0..m.n_type_args).map(|_| SigmaType::SInt).collect();
        let bytes = build_tree(m.type_id, m.method_id, self_box(), args, type_args);
        // Oracle WRAPs (template non-SigmaProp). The node WRAPs a non-landmine (its
        // result is `SAny`) or is LENIENT for a landmine whose `Box` receiver it
        // cannot read as a Coll/Option — both are reject-valid-safe.
        self_pass.push(probe(
            oracle,
            m.type_id,
            m.method_id,
            &m.name,
            &bytes,
            "WRAP",
            &["WRAP", "LENIENT"],
        )?);
    }

    // Landmine pass: SigmaProp-instantiated receivers. Oracle AND node must both
    // type the root SIGMA (the node's projection determines SigmaProp).
    let mut landmine_pass = Vec::new();
    for (type_id, method_id, name, bytes) in landmines() {
        landmine_pass.push(probe(
            oracle,
            type_id,
            method_id,
            name,
            &bytes,
            "SIGMA",
            &["SIGMA"],
        )?);
    }

    // Wrapper pass: every OTHER type-variable method, type var -> SigmaProp. Expect
    // WRAP (an Option[SigmaProp]/Coll[SigmaProp] wrapper is never SigmaProp).
    let mut wrapper_pass = Vec::new();
    for m in methods
        .iter()
        .filter(|m| m.has_type_var && !m.is_landmine())
    {
        let args: Vec<Expr> = (1..m.arity).map(|_| int_const(0)).collect();
        let type_args: Vec<SigmaType> = (0..m.n_type_args).map(|_| SigmaType::SSigmaProp).collect();
        let bytes = build_tree(
            m.type_id,
            m.method_id,
            sigma_receiver_for(m.type_id),
            args,
            type_args,
        );
        // A non-landmine's result is `SAny`, so the node WRAPs (it does not stay
        // lenient) — matching the oracle's WRAP and confirming Phase 3 closes the
        // accept-invalid for these `Option`/`Coll`-wrapper methods.
        wrapper_pass.push(probe(
            oracle,
            m.type_id,
            m.method_id,
            &m.name,
            &bytes,
            "WRAP",
            &["WRAP"],
        )?);
    }

    Ok(Report {
        self_pass,
        landmine_pass,
        wrapper_pass,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::to_hex;

    // ----- oracle parity -----

    /// The 7 landmine trees, pinned to the bytes the JVM oracle classified as
    /// `SIGMA` (sigma-state 6.0.2, `mc_root` surface, has_size v3). These are the
    /// external oracle vectors: a change to the ergo-ser writer or the harness
    /// construction that silently alters a landmine tree is caught here without
    /// needing scala-cli. (Re-confirm with `difftest --methodcall` when changed.)
    #[test]
    fn landmine_trees_match_oracle_verified_bytes() {
        let expected: &[(u8, u8, &str)] = &[
            (12, 10, "0b0bdc0c0a83010808d3010400"),
            (12, 2, "0b0ddc0c0283010808d302040008d3"),
            (12, 5, "0b13dc0c0583010808d30208d3d902010802087201"),
            (36, 3, "0b06db2403e30008"),
            (36, 4, "0b09dc2404e300080108d3"),
            (106, 4, "0b08dc6a04dd010e0008"),
            (106, 5, "0b08dc6a05dd010e0008"),
        ];
        let built = landmines();
        assert_eq!(built.len(), expected.len(), "landmine count");
        for (tid, mid, hex) in expected {
            let (_, _, name, bytes) = built
                .iter()
                .find(|(t, m, _, _)| t == tid && m == mid)
                .unwrap_or_else(|| panic!("landmine ({tid},{mid}) missing"));
            assert_eq!(
                &to_hex(bytes),
                hex,
                "landmine ({tid},{mid}) {name} construction drifted from the oracle-verified tree"
            );
        }
    }

    /// Every registry method parses out cleanly and the landmine set is internally
    /// consistent (all 7 landmine ids are present in the dump and flagged
    /// `has_type_var`).
    #[test]
    fn registry_and_landmine_set_are_consistent() {
        let ms = methods();
        assert_eq!(ms.len(), 199, "expected 199 registered methods");
        for (tid, mid) in LANDMINE_IDS {
            let m = ms
                .iter()
                .find(|m| m.type_id == *tid && m.method_id == *mid)
                .unwrap_or_else(|| panic!("landmine ({tid},{mid}) not in registry"));
            assert!(
                m.has_type_var,
                "landmine ({tid},{mid}) must have a type-variable result"
            );
        }
    }

    /// A SELF-pass tree for a simple property (`SBox.value`) is the expected
    /// has_size v3 PropertyCall — a hermetic check that `build_tree` emits the
    /// shape the oracle classified as `WRAP`.
    #[test]
    fn self_pass_property_tree_shape() {
        // 0b = v3 + has_size; 04 = body length; db = PropertyCall; 63 01 = SBox.value; a7 = SELF.
        let bytes = build_tree(99, 1, self_box(), vec![], vec![]);
        assert_eq!(to_hex(&bytes), "0b04db6301a7");
    }
}
