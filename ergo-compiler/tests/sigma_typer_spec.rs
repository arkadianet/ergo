//! Ported `SigmaTyperTest` integration suite — the M2 acceptance gate.
//!
//! A production-for-production port of every `property(...)` / `ignore(...)` block
//! of the Scala reference test
//! `REF/sc/shared/src/test/scala/sigmastate/lang/SigmaTyperTest.scala`
//! (sigma-state 6.0.2), driven ONLY through the crate's public API
//! (`ergo_compiler::{typecheck, typecheck_with_network, ...}`) plus the reachable
//! typer-internal `unify`/`msg_type` surface for the three type-machinery
//! properties.  The Scala file is the oracle: expected values are NEVER adjusted to
//! make a test pass.
//!
//! Assertion policy (Task-8 brief):
//! - `typecheck(env, x)          shouldBe SType`  → assert the RESULT TYPE
//!   (`node_tpe`), the suite's primary assertion.
//! - `typecheck(env, x, expected)`               → additionally assert the printed
//!   canonical s-expr against a LIVE-oracle capture committed to `golden_seed.txt`
//!   §15 (this test is file-driven over those records: [`seed_ok`]).
//! - `typefail(env, x, line, col)` → E12: assert REJECT + exception CLASS (verdict +
//!   `TyperException`-family / `ParserException`, the same set Scala's `typefail`
//!   accepts).  `TypedExpr` carries no positions, so the typer cannot cite the
//!   `(line, col)`; each port records the original position in an `// original:`
//!   comment for a future position pass.
//!
//! Env (`LangTests.scala:52-69`): the value-typed free variables the suite binds.
//! `EnvValue` carries values only (E9); the SType-valued `typeEnv` slice of Scala's
//! env is therefore always empty (the predef-func env alone seeds the typer).
//! `big` (java `BigInteger`) and `bigIntArr1` (`Coll[BigInt]`) are omitted — they are
//! unrepresentable in `EnvValue` AND unreferenced by any typer property.
//!
//! tree_version = 3 (v6) everywhere except the two version-gate sub-cases which pin
//! the v5 (tree_version = 2) reject explicitly.

use ergo_compiler::typer::unify::{apply_subst, msg_type, msg_type_of, unify_types, TypeSubst};
use ergo_compiler::{
    node_tpe, parse_type, print_typed, typecheck, typecheck_with_network, CompileError, EnvValue,
    GroupElement, NetworkPrefix, SType, ScriptEnv,
};
use SType::{
    NoType, SAny, SBigInt, SBoolean, SBox, SByte, SGroupElement, SInt, SLong, SShort, SSigmaProp,
    SUnit,
};

// ============================================================================
// Helper prelude (mirrors LangTests.scala:52-72 + the SigmaTyperTest helpers).
// ============================================================================

/// The secp256k1 generator point, SEC1-compressed (LangTests `g1`/`g2` are
/// `dlogGroup.generator` and its square; only their TYPE — `GroupElement` — is
/// asserted by any typer property, so the concrete point is immaterial and the
/// generator stands in for both, matching the oracle's `demoEnv`).
fn generator_ge() -> GroupElement {
    let mut bytes = [0u8; 33];
    bytes[0] = 0x02;
    let x = hex::decode("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
        .expect("valid hex");
    bytes[1..].copy_from_slice(&x);
    GroupElement::from_bytes(bytes)
}

/// The SigmaTyperTest env (`LangTests.scala:52-69`), restricted to the entries any
/// typer property references, mapped to `EnvValue` (E9).  Raw LangTests values are
/// written as the constants `Platform.liftToConstant` produces from them
/// (`CAnyValue(10)` → `IntConstant(10)`, a `ProveDlog` → an opaque `SigmaProp`
/// constant whose TYPE is `SSigmaProp`).
fn env() -> ScriptEnv {
    let mut e = ScriptEnv::new();
    e.insert("x", EnvValue::Int(10));
    e.insert("y", EnvValue::Int(11));
    e.insert("c1", EnvValue::Bool(true));
    e.insert("c2", EnvValue::Bool(false));
    e.insert("height1", EnvValue::Long(100));
    e.insert("height2", EnvValue::Long(200));
    e.insert("b1", EnvValue::Byte(1));
    e.insert("b2", EnvValue::Byte(2));
    e.insert("arr1", EnvValue::ByteArray(vec![1, 2]));
    e.insert("arr2", EnvValue::ByteArray(vec![10, 20]));
    e.insert("col1", EnvValue::LongArray(vec![1, 2]));
    e.insert("col2", EnvValue::LongArray(vec![10, 20]));
    e.insert("g1", EnvValue::GroupElement(generator_ge()));
    e.insert("g2", EnvValue::GroupElement(generator_ge()));
    // p1/p2 are ProveDlog SigmaBooleans in LangTests; only `: SSigmaProp` is ever
    // asserted, so an opaque SigmaProp payload is behavior-preserving here.
    e.insert("p1", EnvValue::SigmaProp("p1".to_string()));
    e.insert("p2", EnvValue::SigmaProp("p2".to_string()));
    e.insert("n1", EnvValue::BigInt("10".to_string()));
    e.insert("n2", EnvValue::BigInt("20".to_string()));
    e
}

// ----- type constructors -----

fn coll(t: SType) -> SType {
    SType::SColl(Box::new(t))
}
fn opt(t: SType) -> SType {
    SType::SOption(Box::new(t))
}
fn tuple(ts: Vec<SType>) -> SType {
    SType::STuple(ts)
}
fn func(dom: Vec<SType>, range: SType) -> SType {
    SType::SFunc {
        dom,
        range: Box::new(range),
        tpe_params: vec![],
    }
}
fn coll_byte() -> SType {
    coll(SByte)
}

// ----- typecheck drivers -----

/// `typecheck(env, x) shouldBe expectedType` — assert the result type (the demo
/// env; unreferenced entries are harmless).
fn tpe(src: &str) -> SType {
    node_tpe(&typecheck(&env(), src, 3).unwrap_or_else(|e| panic!("{src:?}: {e:?}"))).clone()
}

/// Like [`tpe`] but at an explicit tree_version (the v5/v6 gate).
fn tpe_v(src: &str, v: u8) -> SType {
    node_tpe(&typecheck(&env(), src, v).unwrap_or_else(|e| panic!("{src:?}@v{v}: {e:?}"))).clone()
}

/// Like [`tpe`] but with a caller-supplied env (properties that augment `env`).
fn tpe_in(e: &ScriptEnv, src: &str) -> SType {
    node_tpe(&typecheck(e, src, 3).unwrap_or_else(|err| panic!("{src:?}: {err:?}"))).clone()
}

/// `typecheck(env, x, expected)` — assert the printed s-expr against the committed
/// oracle capture (`golden_seed.txt`, verb `tc` = empty env / `tcs` = SigmaTyperTest
/// env), then return the result type so the caller can also assert `shouldBe SType`.
fn shape(verb: &str, src: &str) -> SType {
    let e = match verb {
        "tc" => ScriptEnv::new(),
        "tcs" => env(),
        _ => panic!("unknown verb {verb}"),
    };
    let typed = typecheck(&e, src, 3).unwrap_or_else(|err| panic!("{src:?}: {err:?}"));
    assert_eq!(
        print_typed(&typed),
        seed_ok(verb, src),
        "shape mismatch for {src:?}"
    );
    node_tpe(&typed).clone()
}

/// E12 typefail: assert REJECT + exception CLASS.  The Scala `typefail` accepts a
/// `TyperException`-family exception OR a `ParserException`; the exact class comes
/// from the live oracle (captured per call).  `TypedExpr` carries no positions, so
/// the original `(line, col)` is recorded in an `// original:` comment, not asserted.
fn typefail(src: &str, class: &str) {
    let err = match typecheck(&env(), src, 3) {
        Ok(t) => panic!("{src:?}: expected reject, got OK {}", print_typed(&t)),
        Err(e) => e,
    };
    assert!(
        matches!(err, CompileError::Type(_) | CompileError::Parse(_)),
        "{src:?}: expected typer/parser reject, got {err:?}"
    );
    assert_eq!(err.class(), class, "{src:?}: exception class");
}

/// Look up the committed oracle `OK <sexpr>` for `(verb, source)` in the golden
/// seed.  The seed is embedded at compile time, so the shape assertions cannot
/// silently drift from the authoritative capture; §15 records are swept here.
fn seed_ok(verb: &str, src: &str) -> String {
    let seed = include_str!("../../test-vectors/ergoscript/typer/golden_seed.txt");
    for line in seed.lines() {
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.splitn(3, '\t').collect();
        if parts.len() == 3 && parts[0] == verb && parts[1] == src {
            return parts[2]
                .strip_prefix("OK ")
                .unwrap_or_else(|| panic!("seed record for {src:?} is not OK: {}", parts[2]))
                .to_string();
        }
    }
    panic!("no seed OK record for verb={verb} source={src:?}");
}

// ----- unify / msgType machinery helpers (mirror the Scala `ty`/`check`/`unify`) -----

/// `ty(s)` — `SigmaParser.parseType(s)` (LangTests.scala:72).
fn ty(s: &str) -> SType {
    parse_type(s, 3).unwrap_or_else(|e| panic!("parseType {s:?}: {e:?}"))
}
/// The empty substitution (`EmptySubst`).
fn empty_subst() -> TypeSubst {
    TypeSubst::new()
}
/// A concrete substitution from `(varName, type)` pairs.
fn subst(pairs: &[(&str, SType)]) -> TypeSubst {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.clone()))
        .collect()
}

// ============================================================================
// Ported properties (SigmaTyperTest.scala, file order).
// ============================================================================

// SigmaTyperTest.scala:79-110
#[test]
fn simple_expressions() {
    assert_eq!(shape("tcs", "x"), SInt); // constants are substituted from env
    assert_eq!(shape("tcs", "x + y"), SInt);
    assert_eq!(shape("tcs", "x + height1"), SLong);
    assert_eq!(tpe("x - y"), SInt);
    assert_eq!(tpe("x / y"), SInt);
    assert_eq!(tpe("x % y"), SInt);
    assert_eq!(shape("tcs", "c1 && c2"), SBoolean);
    assert_eq!(shape("tcs", "arr1"), coll_byte());
    assert_eq!(shape("tc", "HEIGHT"), SInt);
    assert_eq!(tpe("HEIGHT + 1"), SInt);
    assert_eq!(shape("tc", "INPUTS"), coll(SBox));
    assert_eq!(tpe("INPUTS.size"), SInt);
    assert_eq!(shape("tc", "INPUTS.size > 1"), SBoolean);
    assert_eq!(shape("tcs", "xor(arr1, arr2)"), coll_byte());
    assert_eq!(shape("tcs", "arr1 ++ arr2"), coll_byte());
    assert_eq!(tpe("col1 ++ col2"), coll(SLong));
    assert_eq!(tpe("g1.exp(n1)"), SGroupElement);
    assert_eq!(tpe("g1 * g2"), SGroupElement);
    assert_eq!(tpe("p1 || p2"), SSigmaProp);
    assert_eq!(tpe("p1 && p2"), SSigmaProp);
    assert_eq!(tpe("b1 < b2"), SBoolean);
    assert_eq!(tpe("b1 > b2"), SBoolean);
    assert_eq!(tpe("b1 <= b2"), SBoolean);
    assert_eq!(tpe("b1 >= b2"), SBoolean);
    assert_eq!(tpe("n1 < n2"), SBoolean);
    assert_eq!(tpe("n1 > n2"), SBoolean);
    assert_eq!(tpe("n1 <= n2"), SBoolean);
    assert_eq!(tpe("n1 >= n2"), SBoolean);
    assert_eq!(tpe("n1 == n2"), SBoolean);
    assert_eq!(tpe("n1 != n2"), SBoolean);
}

// SigmaTyperTest.scala:112-142
#[test]
fn predefined_functions() {
    // `allOf` bare → its declaration type `(Coll[Boolean]) => Boolean`
    // (AllOfFunc.declaration.tpe; oracle-confirmed).
    assert_eq!(tpe("allOf"), func(vec![coll(SBoolean)], SBoolean));
    assert_eq!(tpe("allOf(Coll(c1, c2))"), SBoolean);
    assert_eq!(tpe("getVar[Byte](10).get"), SByte);
    assert_eq!(tpe("getVar[Coll[Byte]](10).get"), coll_byte());
    assert_eq!(tpe("getVar[SigmaProp](10).get"), SSigmaProp);
    assert_eq!(tpe("p1 && getVar[SigmaProp](10).get"), SSigmaProp);
    assert_eq!(tpe("getVar[SigmaProp](10).get || p2"), SSigmaProp);
    assert_eq!(
        tpe("getVar[SigmaProp](10).get && getVar[SigmaProp](11).get"),
        SSigmaProp
    );
    assert_eq!(tpe("Coll(true, getVar[SigmaProp](11).get)"), coll(SBoolean));
    assert_eq!(tpe("min(1, 2)"), SInt);
    assert_eq!(tpe("min(1L, 2)"), SLong);
    assert_eq!(tpe("min(HEIGHT, INPUTS.size)"), SInt);
    assert_eq!(tpe("max(1, 2)"), SInt);
    assert_eq!(tpe("max(1L, 2)"), SLong);
    assert_eq!(tpe(r#"bigInt("1111")"#), SBigInt);
    assert_eq!(tpe(r#"fromBase16("1111")"#), coll_byte());
    assert_eq!(tpe(r#"fromBase58("111")"#), coll_byte());
    assert_eq!(tpe(r#"fromBase64("111")"#), coll_byte());

    // PK(<valid P2PK address>) → SSigmaProp.  The Scala test builds the address with
    // TestnetNetworkPrefix; we compile it with the network-aware entry point using
    // the committed testnet address for the secp256k1 generator (golden_seed.txt §10).
    let pk_addr = r#"PK("3WwXpssaZwcNzaGMv3AgxBdTPJQBt5gCmqBsg3DykQ39bYdhJBsN")"#;
    let typed =
        typecheck_with_network(&env(), pk_addr, 3, NetworkPrefix::Testnet).expect("PK typechecks");
    assert_eq!(*node_tpe(&typed), SSigmaProp);

    assert_eq!(tpe("sigmaProp(HEIGHT > 1000)"), SSigmaProp);
    assert_eq!(tpe("ZKProof { sigmaProp(HEIGHT > 1000) }"), SBoolean);
}

// SigmaTyperTest.scala:144-155
#[test]
fn val_constructs() {
    assert_eq!(tpe("{val X = 10; X > 2}"), SBoolean);
    assert_eq!(tpe("{val X = 10; X >= X}"), SBoolean);
    assert_eq!(tpe("{val X = 10 + 1; X >= X}"), SBoolean);
    assert_eq!(tpe("{val X = 10\nval Y = X + 1\nX < Y}\n      "), SBoolean);
    assert_eq!(tpe("{val X = (10, true); X._1 > 2 && X._2}"), SBoolean);
    assert_eq!(
        tpe("{val X = (Coll(1,2,3), 1); X}"),
        tuple(vec![coll(SInt), SInt])
    );
}

// SigmaTyperTest.scala:157-168
#[test]
fn generic_methods_of_arrays() {
    // env ++ ("minToRaise" -> LongConstant(1000)).
    let mut e = env();
    e.insert("minToRaise", EnvValue::Long(1000));
    assert_eq!(
        tpe_in(&e, "OUTPUTS.map({ (out: Box) => out.value >= minToRaise })"),
        ty("Coll[Boolean]")
    );
    assert_eq!(
        tpe_in(
            &e,
            "OUTPUTS.exists({ (out: Box) => out.value >= minToRaise })"
        ),
        SBoolean
    );
    assert_eq!(
        tpe_in(
            &e,
            "OUTPUTS.forall({ (out: Box) => out.value >= minToRaise })"
        ),
        SBoolean
    );
    assert_eq!(
        tpe_in(
            &e,
            "{ val arr = Coll(1,2,3); arr.fold(0, { (i1: Int, i2: Int) => i1 + i2 })}"
        ),
        SInt
    );
    assert_eq!(tpe_in(&e, "OUTPUTS.slice(0, 10)"), ty("Coll[Box]"));
    assert_eq!(
        tpe_in(
            &e,
            "OUTPUTS.filter({ (out: Box) => out.value >= minToRaise })"
        ),
        ty("Coll[Box]")
    );
}

// SigmaTyperTest.scala:170-189
#[test]
fn tuple_constructor() {
    assert_eq!(tpe("()"), SUnit);
    assert_eq!(tpe("(1)"), SInt);
    assert_eq!(tpe("(1, 2)"), tuple(vec![SInt, SInt]));
    assert_eq!(tpe("(1, x + 1)"), tuple(vec![SInt, SInt]));
    assert_eq!(tpe("(1, 2, 3)"), tuple(vec![SInt, SInt, SInt]));
    assert_eq!(tpe("(1, 2 + 3, 4)"), tuple(vec![SInt, SInt, SInt]));

    assert_eq!(tpe("(1, 2L)._1"), SInt);
    assert_eq!(tpe("(1, 2L)._2"), SLong);
    assert_eq!(tpe("(1, 2L, 3)._3"), SInt);

    typefail("(1, 2L)._3", "MethodNotFound"); // original: (1, 1)

    // tuple as collection
    assert_eq!(tpe("(1, 2L).size"), SInt);
    assert_eq!(tpe("(1, 2L)(0)"), SInt);
    assert_eq!(tpe("(1, 2L)(1)"), SLong);
    assert_eq!(tpe("{ (a: Int) => (1, 2L)(a) }"), func(vec![SInt], SAny));
}

// SigmaTyperTest.scala:191-194 — Scala `ignore(...)`; mirrored as #[ignore].
#[test]
#[ignore = "mirrors Scala ignore(\"tuple advanced operations\") — getOrElse/slice on tuple receivers unsupported"]
fn tuple_advanced_operations() {
    assert_eq!(tpe("(1, 2L).getOrElse(2, 3)"), SAny);
    assert_eq!(tpe("(1, 2L).slice(0, 2)"), coll(SAny));
}

// SigmaTyperTest.scala:196-203
#[test]
fn types() {
    assert_eq!(tpe("{val X: Int = 10; 3 > 2}"), SBoolean);
    assert_eq!(tpe("{val X: (Int, Boolean) = (10, true); 3 > 2}"), SBoolean);
    assert_eq!(tpe("{val X: Coll[Int] = Coll(1,2,3); X.size}"), SInt);
    assert_eq!(
        tpe("{val X: (Coll[Int], Int) = (Coll(1,2,3), 1); X}"),
        tuple(vec![coll(SInt), SInt])
    );
    assert_eq!(
        tpe("{val X: (Coll[Int], Int) = (Coll(1,2,3), x); X._1}"),
        coll(SInt)
    );
    assert_eq!(
        tpe("{val X: (Coll[Int], Int) = (Coll(1,2,3), x); X._1}"),
        coll(SInt)
    );
}

// SigmaTyperTest.scala:205-214
#[test]
fn if_() {
    assert_eq!(tpe("if(true) 1 else 2"), SInt);
    assert_eq!(tpe("if(c1) 1 else 2"), SInt);
    assert_eq!(tpe("if(c1) x else y"), SInt);
    assert_eq!(
        tpe("if (true) {\n  val A = 10; A\n} else\n  if ( x == y) 2 else 3"),
        SInt
    );
}

// SigmaTyperTest.scala:216-227
#[test]
fn array_literals() {
    typefail("Coll()", "TyperException"); // original: (1, 1)
    typefail("Coll(Coll())", "TyperException"); // original: (1, 6)
    typefail("Coll(Coll(Coll()))", "TyperException"); // original: (1, 11)

    assert_eq!(tpe("Coll(1)"), coll(SInt));
    assert_eq!(tpe("Coll(1, x)"), coll(SInt));
    assert_eq!(tpe("Coll(Coll(x + 1))"), coll(coll(SInt)));

    typefail("Coll(1, x + 1, Coll())", "TyperException"); // original: (1, 16)
    typefail("Coll(1, false)", "TyperException"); // original: (1, 1)
}

// SigmaTyperTest.scala:229-232
#[test]
fn methods_returning_option() {
    assert_eq!(tpe("getVar[Int](10)"), opt(SInt));
    assert_eq!(tpe("{ val v = getVar[Int](1); v.get }"), SInt);
}

// SigmaTyperTest.scala:234-238
#[test]
fn array_indexed_access() {
    typefail("Coll()(0)", "TyperException"); // original: (1, 1)
    assert_eq!(tpe("Coll(0)(0)"), SInt);
    typefail("Coll(0)(0)(0)", "TyperException"); // original: (1, 1)
}

// SigmaTyperTest.scala:240-245
#[test]
fn array_indexed_access_with_evaluation() {
    assert_eq!(tpe("Coll(0)(1 - 1)"), SInt);
    assert_eq!(tpe("Coll(0)((1 - 1) + 0)"), SInt);
    typefail("Coll(0)(0 == 0)", "TyperException"); // original: (1, 9)
    typefail("Coll(0)(1,1,1)", "TyperException"); // original: (1, 1)
}

// SigmaTyperTest.scala:247-252
#[test]
fn array_indexed_access_with_default_value() {
    assert_eq!(tpe("Coll(0).getOrElse(0, 1)"), SInt);
    typefail("Coll(0).getOrElse(true, 1)", "TyperException"); // original: (1, 1)
    typefail("Coll(true).getOrElse(0, 1)", "TyperException"); // original: (1, 1)
    typefail("Coll(0).getOrElse(0, Coll(1))", "TyperException"); // original: (1, 1)
}

// SigmaTyperTest.scala:254-256
#[test]
fn array_indexed_access_with_default_value_with_evaluation() {
    assert_eq!(tpe("Coll(0).getOrElse(0, (2 - 1) + 0)"), SInt);
}

// SigmaTyperTest.scala:258-269
#[test]
fn lambdas() {
    assert_eq!(tpe("{ (a: Int) => a + 1 }"), func(vec![SInt], SInt));
    assert_eq!(tpe("{ (a: Int) => a + 1 }"), func(vec![SInt], SInt));
    assert_eq!(tpe("{ (a: Int) => { a + 1 } }"), func(vec![SInt], SInt));
    assert_eq!(
        tpe("{ (a: Int) => { val b = a + 1; b } }"),
        func(vec![SInt], SInt)
    );
    assert_eq!(
        tpe("{ (a: Int, box: Box) => a + box.value }"),
        func(vec![SInt, SBox], SLong)
    );
    assert_eq!(
        tpe("{ (p: (Int, SigmaProp), box: Box) => p._1 > box.value && p._2.isProven }"),
        func(vec![tuple(vec![SInt, SSigmaProp]), SBox], SBoolean)
    );

    typefail("{ (a) => a + 1 }", "TyperException"); // original: (1, 3)
}

// SigmaTyperTest.scala:271-273
#[test]
fn function_definitions_via_val() {
    assert_eq!(
        tpe("{ val f = { (x: Int) => x + 1 }; f }"),
        func(vec![SInt], SInt)
    );
}

// SigmaTyperTest.scala:275-277
#[test]
fn function_definitions() {
    assert_eq!(
        tpe("{ def f(x: Int) = { x + 1 }; f }"),
        func(vec![SInt], SInt)
    );
}

// SigmaTyperTest.scala:279-289 — `an[TyperException] should be thrownBy`.
#[test]
fn recursive_function_definitions() {
    typefail(
        "{\n  def f(x: Int) = if (x / 2 == 0) g(x) else x\n  def g(x: Int) = f(x + 1)\n  g(1)\n}\n      ",
        "TyperException",
    );
}

// SigmaTyperTest.scala:291-298
#[test]
fn predefined_primitives() {
    assert_eq!(tpe("{ (box: Box) => box.value }"), func(vec![SBox], SLong));
    assert_eq!(
        tpe("{ (box: Box) => box.propositionBytes }"),
        func(vec![SBox], coll_byte())
    );
    assert_eq!(
        tpe("{ (box: Box) => box.bytes }"),
        func(vec![SBox], coll_byte())
    );
    assert_eq!(
        tpe("{ (box: Box) => box.id }"),
        func(vec![SBox], coll_byte())
    );
    // ExtractCreationInfo.ResultType = (Int, Coll[Byte]) (oracle-confirmed).
    assert_eq!(
        tpe("{ (box: Box) => box.creationInfo }"),
        func(vec![SBox], tuple(vec![SInt, coll_byte()]))
    );
}

// SigmaTyperTest.scala:300-311
#[test]
fn type_parameters() {
    assert_eq!(tpe("SELF.R1[Int]"), opt(SInt));
    assert_eq!(tpe("SELF.R1[Int].isDefined"), SBoolean);
    assert_eq!(tpe("SELF.R1[Int].isEmpty"), SBoolean);
    assert_eq!(tpe("SELF.R1[Int].get"), SInt);
    typefail("x[Int]", "TyperException"); // original: (1, 1)
    typefail("arr1[Int]", "TyperException"); // original: (1, 1)
    assert_eq!(
        tpe("SELF.R1[(Int,Boolean)]"),
        opt(tuple(vec![SInt, SBoolean]))
    );
    assert_eq!(
        tpe("SELF.R1[(Int,Boolean)].get"),
        tuple(vec![SInt, SBoolean])
    );
    typefail("SELF.R1[Int,Boolean].get", "TyperException"); // original: (1, 6)
    assert_eq!(tpe("Coll[Int]()"), coll(SInt));
}

// SigmaTyperTest.scala:313-322 — unifyTypes over the predefined types.  The Scala
// `forAll { t: SPredefType => ... }` is ported as an enumeration over the concrete
// predefined types (Rust has no ScalaCheck SPredefType generator); this is at least
// as strong as the sampled property.
#[test]
fn compute_unifying_type_substitution_prim_types() {
    let predef = [
        SBoolean,
        SByte,
        SShort,
        SInt,
        SLong,
        SBigInt,
        SGroupElement,
        SSigmaProp,
        SBox,
        SType::SAvlTree,
        SUnit,
    ];
    for t in predef {
        assert_eq!(unify_types(&t, &t), Some(empty_subst()));
        assert_eq!(unify_types(&SAny, &t), Some(empty_subst()));
        assert_eq!(unify_types(&SAny, &coll(t.clone())), Some(empty_subst()));
        assert_eq!(
            unify_types(&coll(SAny), &coll(t.clone())),
            Some(empty_subst())
        );
        assert_eq!(
            unify_types(&coll(SAny), &tuple(vec![t.clone(), t.clone(), t.clone()])),
            Some(empty_subst())
        );
        assert_eq!(
            unify_types(
                &coll(SAny),
                &tuple(vec![t.clone(), tuple(vec![t.clone(), t.clone()])])
            ),
            Some(empty_subst())
        );
    }
}

// SigmaTyperTest.scala:324-422
#[test]
fn compute_unifying_type_substitution() {
    // checkTypes(t1, t2, exp): unify == exp, and (Some) unify(applySubst(t1), t2) == empty.
    fn check_types(t1: &SType, t2: &SType, exp: Option<TypeSubst>) {
        assert_eq!(unify_types(t1, t2), exp, "unify({t1:?}, {t2:?})");
        if let Some(s) = &exp {
            assert_eq!(
                unify_types(&apply_subst(t1, s), t2),
                Some(empty_subst()),
                "applySubst consistency for {t1:?}"
            );
        }
    }
    // check(s1, s2, exp = Some(empty)).
    let check = |s1: &str, s2: &str, exp: Option<TypeSubst>| check_types(&ty(s1), &ty(s2), exp);
    let some_empty = || Some(empty_subst());
    // unify(s1, s2, subst): expect Some(subst).
    let unify = |s1: &str, s2: &str, pairs: &[(&str, SType)]| {
        check_types(&ty(s1), &ty(s2), Some(subst(pairs)))
    };

    assert_eq!(unify_types(&NoType, &NoType), None);
    assert_eq!(unify_types(&SLong, &SBoolean), None);

    check("(Int, Boolean)", "Int", None);
    check("(Int, Boolean)", "(Int, Boolean)", some_empty());
    check("(Int, Boolean)", "(Int, Int)", None);
    check("(Int, Box)", "(Int, Box)", some_empty());
    check("(Int, Box)", "(Int, Box, Boolean)", None);

    check("Coll[Any]", "(Int, Long)", some_empty()); // tuple as array
    check("Coll[Coll[Any]]", "Coll[(Int, Long)]", some_empty());

    check("Coll[Int]", "Coll[Boolean]", None);
    check("Coll[Int]", "Coll[Int]", some_empty());
    check("Coll[(Int,Box)]", "Coll[Int]", None);
    check("Coll[(Int,Box)]", "Coll[(Int,Box)]", some_empty());
    check("Coll[Coll[Int]]", "Coll[Coll[Int]]", some_empty());

    check("Option[Int]", "Option[Boolean]", None);
    check("Option[Int]", "Option[Int]", some_empty());
    check("Option[(Int,Box)]", "Option[Int]", None);
    check("Option[(Int,Box)]", "Option[(Int,Box)]", some_empty());
    check("Option[Option[Int]]", "Option[Option[Int]]", some_empty());

    check("Int => Int", "Int => Boolean", None);
    check("Int => Int", "Int => Int", some_empty());
    check("(Int, Boolean) => Int", "Int => Int", None);
    check(
        "(Int, Boolean) => Int",
        "(Int,Boolean) => Int",
        some_empty(),
    );

    unify("A", "A", &[]);
    check("A", "B", None);

    check("(Int, A)", "Int", None);
    unify("(Int, A)", "(Int, A)", &[]);
    unify("(Int, A)", "(Int, Int)", &[("A", SInt)]);
    unify("(A, B)", "(A, B)", &[]);
    unify("(A, B)", "(Int, Boolean)", &[("A", SInt), ("B", SBoolean)]);
    check("(A, B)", "(Int, Boolean, Box)", None);
    check("(A, Boolean)", "(Int, B)", None);
    check("(A, Int)", "(B, Int)", None);

    unify("A", "Coll[Boolean]", &[("A", ty("Coll[Boolean]"))]);
    unify("Coll[A]", "Coll[Int]", &[("A", SInt)]);
    unify("Coll[A]", "Coll[(Int, Box)]", &[("A", ty("(Int, Box)"))]);
    unify("Coll[(Int, A)]", "Coll[(Int, Box)]", &[("A", SBox)]);
    unify("Coll[Coll[A]]", "Coll[Coll[Int]]", &[("A", SInt)]);
    unify("Coll[Coll[A]]", "Coll[Coll[A]]", &[]);
    check("Coll[Coll[A]]", "Coll[Coll[B]]", None);

    unify("A", "Option[Boolean]", &[("A", ty("Option[Boolean]"))]);
    unify("Option[A]", "Option[Int]", &[("A", SInt)]);
    unify(
        "Option[A]",
        "Option[(Int, Box)]",
        &[("A", ty("(Int, Box)"))],
    );
    unify("Option[(Int, A)]", "Option[(Int, Box)]", &[("A", SBox)]);
    unify("Option[Option[A]]", "Option[Option[Int]]", &[("A", SInt)]);
    unify("Option[Option[A]]", "Option[Option[A]]", &[]);
    check("Option[Option[A]]", "Option[Option[B]]", None);

    unify("A => Int", "Int => Int", &[("A", SInt)]);
    check("A => Int", "Int => Boolean", None);
    unify("Int => A", "Int => Int", &[("A", SInt)]);
    check("Int => A", "Boolean => Int", None);
    unify(
        "(Int, A) => B",
        "(Int, Boolean) => Box",
        &[("A", SBoolean), ("B", SBox)],
    );
    check("(Int, A) => A", "(Int, Boolean) => Box", None);
    unify(
        "(Int, A) => A",
        "(Int, Boolean) => Boolean",
        &[("A", SBoolean)],
    );

    unify(
        "((A,Int), Coll[B] => Coll[(Coll[C], B)]) => A",
        "((Int,Int), Coll[Boolean] => Coll[(Coll[C], Boolean)]) => Int",
        &[("A", SInt), ("B", SBoolean)],
    );

    assert_eq!(unify_types(&SBoolean, &SSigmaProp), Some(empty_subst()));
    assert_eq!(unify_types(&SSigmaProp, &SBoolean), None);
    check("(Int, Boolean)", "(Int, SigmaProp)", some_empty());
    check(
        "(Int, Boolean, Boolean)",
        "(Int, SigmaProp, SigmaProp)",
        some_empty(),
    );
    check("Coll[Boolean]", "Coll[SigmaProp]", some_empty());
    check("Coll[(Int,Boolean)]", "Coll[(Int,SigmaProp)]", some_empty());
    check("Coll[Coll[Boolean]]", "Coll[Coll[SigmaProp]]", some_empty());
    check("Option[Boolean]", "Option[SigmaProp]", some_empty());
    check(
        "Option[(Int,Boolean)]",
        "Option[(Int,SigmaProp)]",
        some_empty(),
    );
    check(
        "Option[Option[Boolean]]",
        "Option[Option[SigmaProp]]",
        some_empty(),
    );
    check("Int => Boolean", "Int => SigmaProp", some_empty());
    check(
        "(Int, Boolean) => Int",
        "(Int, SigmaProp) => Int",
        some_empty(),
    );
}

// SigmaTyperTest.scala:424-466
#[test]
fn most_specific_general_msg_type() {
    let check_types = |t1: &SType, t2: &SType, exp: Option<SType>| {
        assert_eq!(msg_type(t1, t2), exp, "msgType({t1:?}, {t2:?})");
    };
    let check = |s1: &str, s2: &str, exp: Option<SType>| check_types(&ty(s1), &ty(s2), exp);
    let check_all = |ts: &[&str], exp: Option<SType>| {
        let types: Vec<SType> = ts.iter().map(|s| ty(s)).collect();
        assert_eq!(msg_type_of(&types), exp, "msgTypeOf({ts:?})");
    };

    check_types(&NoType, &NoType, None);
    check_types(&NoType, &SInt, None);
    check_types(&SInt, &SInt, Some(SInt));
    check_types(&SBoolean, &SSigmaProp, Some(SBoolean));
    check_types(&SSigmaProp, &SBoolean, Some(SBoolean));

    check(
        "(Int, Boolean)",
        "(Int, SigmaProp)",
        Some(ty("(Int, Boolean)")),
    );
    check(
        "(Int, SigmaProp)",
        "(Int, Boolean)",
        Some(ty("(Int, Boolean)")),
    );
    check(
        "Coll[Boolean]",
        "Coll[SigmaProp]",
        Some(ty("Coll[Boolean]")),
    );
    check(
        "Coll[SigmaProp]",
        "Coll[Boolean]",
        Some(ty("Coll[Boolean]")),
    );
    check(
        "Coll[(Int,Boolean)]",
        "Coll[(Int,SigmaProp)]",
        Some(ty("Coll[(Int,Boolean)]")),
    );
    check(
        "Coll[(Int,SigmaProp)]",
        "Coll[(Int,Boolean)]",
        Some(ty("Coll[(Int,Boolean)]")),
    );
    check(
        "Coll[Coll[Boolean]]",
        "Coll[Coll[SigmaProp]]",
        Some(ty("Coll[Coll[Boolean]]")),
    );
    check(
        "Coll[Coll[SigmaProp]]",
        "Coll[Coll[Boolean]]",
        Some(ty("Coll[Coll[Boolean]]")),
    );
    check(
        "Option[(Int,Boolean)]",
        "Option[(Int,SigmaProp)]",
        Some(ty("Option[(Int,Boolean)]")),
    );
    check(
        "Option[(Int,SigmaProp)]",
        "Option[(Int,Boolean)]",
        Some(ty("Option[(Int,Boolean)]")),
    );
    check(
        "Option[Option[Boolean]]",
        "Option[Option[SigmaProp]]",
        Some(ty("Option[Option[Boolean]]")),
    );
    check(
        "Option[Option[SigmaProp]]",
        "Option[Option[Boolean]]",
        Some(ty("Option[Option[Boolean]]")),
    );
    check(
        "Int => Boolean",
        "Int => SigmaProp",
        Some(ty("Int => Boolean")),
    );
    check(
        "Int => SigmaProp",
        "Int => Boolean",
        Some(ty("Int => Boolean")),
    );

    check_all(&["Boolean", "SigmaProp"], Some(SBoolean));
    check_all(&["Boolean", "SigmaProp", "Boolean"], Some(SBoolean));
    check_all(&["Boolean", "SigmaProp", "Int"], None);
    check_all(&["Int", "Int", "Int"], Some(SInt));
    check_all(
        &["(Int, Boolean)", "(Int,SigmaProp)", "(Int,Boolean)"],
        Some(ty("(Int,Boolean)")),
    );
}

// SigmaTyperTest.scala:468-486
#[test]
fn invalid_binary_operations_type_check() {
    typefail("1 == false", "InvalidBinaryOperationParameters"); // original: (1, 1)
    typefail("1 != false", "InvalidBinaryOperationParameters"); // original: (1, 1)
    typefail("1 > false", "InvalidBinaryOperationParameters"); // original: (1, 1)
    typefail("1 < false", "InvalidBinaryOperationParameters"); // original: (1, 1)
    typefail("1 + false", "InvalidBinaryOperationParameters"); // original: (1, 5)
    typefail("1 - false", "InvalidBinaryOperationParameters"); // original: (1, 1)
    typefail("1 / false", "InvalidBinaryOperationParameters"); // original: (1, 1)
    typefail("1 % false", "InvalidBinaryOperationParameters"); // original: (1, 1)
    typefail("min(1, false)", "InvalidBinaryOperationParameters"); // original: (1, 5)
    typefail("max(1, false)", "InvalidBinaryOperationParameters"); // original: (1, 5)
    typefail("1 * false", "InvalidBinaryOperationParameters"); // original: (1, 5)
    typefail("1 + \"a\"", "InvalidBinaryOperationParameters"); // original: (1, 5)
    typefail("1 || 1", "NonApplicableMethod"); // original: (1, 1)
    typefail("col1 || col2", "NonApplicableMethod"); // original: (1, 1)
    typefail("g1 || g2", "NonApplicableMethod"); // original: (1, 1)
    typefail("true ++ false", "NonApplicableMethod"); // original: (1, 1)
    typefail("\"a\" ++ \"a\"", "NonApplicableMethod"); // original: (1, 1)
}

// SigmaTyperTest.scala:488-499
#[test]
fn upcast_for_binary_operations_with_numeric_types() {
    assert_eq!(tpe("1 == 1L"), SBoolean);
    assert_eq!(tpe("1 > 1L"), SBoolean);
    assert_eq!(tpe("1 >= 1L"), SBoolean);
    assert_eq!(tpe("1 < 1L"), SBoolean);
    assert_eq!(tpe("1 <= 1L"), SBoolean);
    assert_eq!(tpe("1 + 1L"), SLong);
    assert_eq!(tpe("1 - 1L"), SLong);
    assert_eq!(tpe("1 * 1L"), SLong);
    assert_eq!(tpe("1 / 1L"), SLong);
    assert_eq!(tpe("1 % 1L"), SLong);
}

// SigmaTyperTest.scala:501-509
#[test]
fn casts_for_numeric_types() {
    assert_eq!(tpe("1.toByte"), SByte);
    assert_eq!(tpe("1.toShort"), SShort);
    assert_eq!(tpe("1L.toInt"), SInt);
    assert_eq!(tpe("1.toLong"), SLong);
    assert_eq!(tpe("1.toBigInt"), SBigInt);
    assert_eq!(tpe("1L * 1.toLong"), SLong);
}

// SigmaTyperTest.scala:511-513
#[test]
fn invalid_cast_method_for_numeric_types() {
    typefail("1.toSuperBigInteger", "MethodNotFound"); // original: (1, 1)
}

// SigmaTyperTest.scala:515-555 — `.toBytes` numeric method-call survivors; the Scala
// test asserts the full MethodCall tree, so both shape and type are checked.
#[test]
fn to_bytes_method_for_numeric_types() {
    assert_eq!(shape("tc", "1.toByte.toBytes"), coll_byte());
    assert_eq!(shape("tc", "1.toShort.toBytes"), coll_byte());
    assert_eq!(shape("tc", "1.toBytes"), coll_byte());
    assert_eq!(shape("tc", "1.toLong.toBytes"), coll_byte());
    assert_eq!(shape("tc", "1.toBigInt.toBytes"), coll_byte());
}

// SigmaTyperTest.scala:557-559
#[test]
fn string_concat() {
    assert_eq!(tpe(r#" "a" + "b" "#), SType::SString);
}

// SigmaTyperTest.scala:561-569 — Scala `ignore(...)`; mirrored as #[ignore].
#[test]
#[ignore = "mirrors Scala ignore(\"modular arith ops\") — TODO sigmastate issue #327 (modQ/plusModQ/minusModQ)"]
fn modular_arith_ops() {
    assert_eq!(tpe("10.toBigInt.modQ"), SBigInt);
    assert_eq!(tpe("10.toBigInt.plusModQ(2.toBigInt)"), SBigInt);
    assert_eq!(tpe("10.toBigInt.minusModQ(2.toBigInt)"), SBigInt);
    typefail("10.modQ", "TyperException"); // original: (1, 1)
    typefail("10.toBigInt.plusModQ(1)", "TyperException"); // original: (1, 1)
    typefail("10.toBigInt.minusModQ(1)", "TyperException"); // original: (1, 1)
}

// SigmaTyperTest.scala:571-574
#[test]
fn byte_array_to_long() {
    assert_eq!(tpe("byteArrayToLong(Coll[Byte](1.toByte))"), SLong);
    typefail("byteArrayToLong(Coll[Int](1))", "TyperException"); // original: (1, 1)
}

// SigmaTyperTest.scala:576-579
#[test]
fn decode_point() {
    assert_eq!(tpe("decodePoint(Coll[Byte](1.toByte))"), SGroupElement);
    typefail("decodePoint(Coll[Int](1))", "TyperException"); // original: (1, 1)
}

// SigmaTyperTest.scala:581-584
#[test]
fn xor_of() {
    assert_eq!(tpe("xorOf(Coll[Boolean](true, false))"), SBoolean);
    typefail("xorOf(Coll[Int](1))", "TyperException"); // original: (1, 1)
}

// SigmaTyperTest.scala:586-595
#[test]
fn outer_join() {
    assert_eq!(
        tpe("outerJoin[Byte, Short, Int, Long](\n Coll[(Byte, Short)]((1.toByte, 2.toShort)),\n Coll[(Byte, Int)]((1.toByte, 3.toInt)),\n { (b: Byte, s: Short) => (b + s).toLong },\n { (b: Byte, i: Int) => (b + i).toLong },\n { (b: Byte, s: Short, i: Int) => (b + s + i).toLong }\n )"),
        coll(tuple(vec![SByte, SLong]))
    );
}

// SigmaTyperTest.scala:597-599
#[test]
fn atleast_invalid_parameters() {
    typefail("atLeast(2, 2)", "TyperException"); // original: (1, 1)
}

// SigmaTyperTest.scala:601-603
#[test]
fn subst_constants() {
    assert_eq!(
        tpe("substConstants[Long](Coll[Byte](1.toByte), Coll[Int](1), Coll[Long](1L))"),
        coll_byte()
    );
}

// SigmaTyperTest.scala:605-607
#[test]
fn execute_from_var() {
    assert_eq!(tpe("executeFromVar[Boolean](1)"), SBoolean);
}

// SigmaTyperTest.scala:609-615
#[test]
fn execute_from_self_reg_with_default() {
    assert_eq!(
        tpe("executeFromSelfRegWithDefault[Boolean](4, getVar[Boolean](1).get)"),
        SBoolean
    );
    // an[TyperException] should be thrownBy — Boolean default vs Int register value.
    typefail(
        "executeFromSelfRegWithDefault[Boolean](4, getVar[Int](1).get)",
        "TyperException",
    );
}

// SigmaTyperTest.scala:617-620
#[test]
fn logical_not() {
    assert_eq!(tpe("!true"), SBoolean);
    typefail(
        "!getVar[SigmaProp](1).get",
        "InvalidUnaryOperationParameters",
    ); // original: (1, 2)
}

// SigmaTyperTest.scala:622-625
#[test]
fn negation() {
    assert_eq!(tpe("-HEIGHT"), SInt);
    // `-true`: Scala rejects at build time (ParserException); our parser matches.
    typefail("-true", "ParserException"); // original: (1, 2)
}

// SigmaTyperTest.scala:627-630
#[test]
fn bit_inversion() {
    assert_eq!(tpe("~1"), SInt);
    typefail("~true", "ParserException"); // original: (1, 2)
}

// SigmaTyperTest.scala:632-634
#[test]
fn logical_xor() {
    assert_eq!(tpe("true ^ false"), SBoolean);
}

// SigmaTyperTest.scala:636-639
#[test]
fn bitwise_or() {
    assert_eq!(tpe("1 | 2"), SInt);
    typefail("true | false", "ParserException"); // original: (1, 1)
}

// SigmaTyperTest.scala:641-644
#[test]
fn bitwise_and() {
    assert_eq!(tpe("1 & 2"), SInt);
    typefail("true & false", "ParserException"); // original: (1, 1)
}

// SigmaTyperTest.scala:646-648
#[test]
fn bitwise_xor() {
    assert_eq!(tpe("1 ^ 2"), SInt);
}

// SigmaTyperTest.scala:650-653
#[test]
fn bit_shift_right() {
    assert_eq!(tpe("1 >> 2"), SInt);
    typefail("true >> false", "NonApplicableMethod"); // original: (1, 1)
}

// SigmaTyperTest.scala:655-658
#[test]
fn bit_shift_left() {
    assert_eq!(tpe("1 << 2"), SInt);
    typefail("true << false", "NonApplicableMethod"); // original: (1, 1)
}

// SigmaTyperTest.scala:660-663
#[test]
fn bit_shift_right_zeroed() {
    assert_eq!(tpe("1 >>> 2"), SInt);
    typefail("true >>> false", "NonApplicableMethod"); // original: (1, 1)
}

// SigmaTyperTest.scala:665-668
#[test]
fn scollection_indices() {
    assert_eq!(tpe("Coll(1).indices"), coll(SInt));
    assert_eq!(tpe("INPUTS.indices"), coll(SInt));
}

// SigmaTyperTest.scala:670-672
#[test]
fn scollection_flatmap() {
    assert_eq!(
        tpe("OUTPUTS.flatMap({ (out: Box) => Coll(out.value >= 1L) })"),
        coll(SBoolean)
    );
}

// SigmaTyperTest.scala:674-676 — ErgoBox.STokensRegType = Coll[(Coll[Byte], Long)].
#[test]
fn sbox_tokens() {
    assert_eq!(tpe("SELF.tokens"), coll(tuple(vec![coll_byte(), SLong])));
}

// SigmaTyperTest.scala:678-680
#[test]
fn scontext_data_inputs() {
    assert_eq!(tpe("CONTEXT.dataInputs"), coll(SBox));
}

// SigmaTyperTest.scala:682-684
#[test]
fn scontext_get_var() {
    assert_eq!(tpe("CONTEXT.getVar[Int](1.toByte).get"), SInt);
}

// SigmaTyperTest.scala:686-690 — runWithVersion(V6) → tree_version = 3.
#[test]
fn scontext_get_var_from_input() {
    assert_eq!(
        tpe_v("CONTEXT.getVarFromInput[Int](1.toShort, 1.toByte).get", 3),
        SInt
    );
}

// SigmaTyperTest.scala:692-694
#[test]
fn savltree_digest() {
    assert_eq!(tpe("getVar[AvlTree](1).get.digest"), coll_byte());
}

// SigmaTyperTest.scala:696-698
#[test]
fn sgroupelement_exp() {
    assert_eq!(tpe("g1.exp(1.toBigInt)"), SGroupElement);
}

// SigmaTyperTest.scala:700-721 — the `substConst` property.
//
// IGNORED (env value unrepresentable): the custom env binds `positions` to a
// `Coll[Int]` (IntArrayConstant) and `newVals` to a `Coll[SigmaProp]`
// (ConcreteCollection[SigmaProp]); `EnvValue` has no Coll[Int] / Coll[SigmaProp]
// variant, and no behavior-preserving substitute exists (a Coll[Int] value cannot be
// lifted through `EnvValue`).  The property's sole assertion — `substConstants(...)
// : SByteArray` — is already covered by `subst_constants` above (line 601, all
// literal args).  Original source below for the future EnvValue extension.
#[test]
#[ignore = "env value unrepresentable: positions Coll[Int] + newVals Coll[SigmaProp] have no EnvValue variant"]
fn subst_const() {
    // customEnv = { scriptBytes: Coll[Byte], positions: Coll[Int], newVals: Coll[SigmaProp], expectedBytes: Coll[Byte] }
    // typecheck(customEnv, "substConstants(scriptBytes, positions, newVals)") shouldBe SByteArray
}

// SigmaTyperTest.scala:723-740 — Global.serialize: v6 shape accept + v5 MethodNotFound.
#[test]
fn global_serialize() {
    // runWithVersion(V6) → tree_version = 3: surviving MethodCall (golden_seed §4).
    let typed = typecheck(&env(), "Global.serialize(1)", 3).expect("v6 accepts");
    assert_eq!(print_typed(&typed), seed_ok("tc", "Global.serialize(1)"));
    assert_eq!(*node_tpe(&typed), coll_byte());

    // runWithVersion(V6 - 1) → tree_version = 2: serialize is v6-only → MethodNotFound.
    let err = typecheck(&env(), "Global.serialize(1)", 2).expect_err("v5 rejects");
    assert_eq!(err.class(), "MethodNotFound");
}

// SigmaTyperTest.scala:742-752 — predefined `serialize` desugars to Global.serialize.
#[test]
fn predefined_serialize() {
    // runWithVersion(V6) → tree_version = 3.
    let typed = typecheck(&env(), "serialize((1, 2L))", 3).expect("v6 accepts");
    assert_eq!(print_typed(&typed), seed_ok("tc", "serialize((1, 2L))"));
    assert_eq!(*node_tpe(&typed), coll_byte());
}

// ----- crate-side deviation cases (M1 D6 interp: the typecheck surface is unchanged
// from parse, so a `${...}`-interpolation source still rejects at parse) -----

/// D6: the reference's id-prefixed `${ Block }` string interpolation is rejected in
/// M1 (`s"a ${x} b"`, lib.rs deviation ledger + `sigma_parser_spec.rs:2108`); the
/// `typecheck` surface inherits that parse reject unchanged.  (A plain unprefixed
/// `"${x}"` treats `${x}` as content and is accepted — the opposite direction.)
#[test]
fn d6_interpolation_block_rejects_at_parse() {
    let err = match typecheck(&env(), "s\"a ${x} b\"", 3) {
        Ok(t) => panic!("expected D6 parse reject, got OK {}", print_typed(&t)),
        Err(e) => e,
    };
    assert!(matches!(err, CompileError::Parse(_)));
}
