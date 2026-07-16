//! ScriptEnv — compile-time constant substitution environment for the binder.
//!
//! Mirrors `sigmastate.interpreter.Interpreter.ScriptEnv` (Scala `Map[String, Any]`,
//! Interpreter.scala:503), restricted to the value types that
//! `Platform.liftToConstant` (data/jvm/src/main/scala/sigma/Platform.scala:16-65)
//! successfully lifts and that appear in the oracle demo env exercised by this
//! crate's golden test vectors.
//!
//! Uses `BTreeMap` for deterministic iteration order (alphabetical by key).

use std::collections::BTreeMap;

use ergo_crypto::group_element::{decompress_to_affine_hex, GroupElementError};
use ergo_primitives::group_element::GroupElement;

use crate::stype::SType;
use crate::typed::{ConstPayload, TypedExpr};

// ── EnvValue ─────────────────────────────────────────────────────────────────

/// A single compile-time constant value in the script environment.
///
/// Covers every value type that `Platform.liftToConstant` handles and that
/// appears in the oracle demo env.  The version-gated arms
/// (java.math.BigInteger at v5 only, sigma.Header/PreHeader/UnsignedBigInt at
/// v6 only) are omitted — they are not reachable from the demo env and the
/// oracle does not exercise them.
///
/// Normative source: Platform.scala:16-65.
#[derive(Debug, Clone, PartialEq)]
pub enum EnvValue {
    /// `Boolean` → `TrueLeaf`/`FalseLeaf`.  Platform.scala:37.
    Bool(bool),
    /// `Byte` (i8) → `ByteConstant`.  Platform.scala:27.
    Byte(i8),
    /// `Short` (i16) → `ShortConstant`.  Platform.scala:29.
    Short(i16),
    /// `Int` (i32) → `IntConstant`.  Platform.scala:31.
    Int(i32),
    /// `Long` (i64) → `LongConstant`.  Platform.scala:33.
    Long(i64),
    /// `sigma.BigInt` → `BigIntConstant`. Decimal string form, e.g. `"5"`.
    /// Platform.scala:35.
    BigInt(String),
    /// `Coll[Byte]` / `Array[Byte]` → `ByteArrayConstant`.  Platform.scala:51-52.
    ByteArray(Vec<i8>),
    /// `Coll[Long]` / `Array[Long]` → `LongArrayConstant`.  Platform.scala:55-56.
    LongArray(Vec<i64>),
    /// `GroupElement` (33-byte SEC1-compressed secp256k1 point) →
    /// `GroupElementConstant`.  Platform.scala:39-41.
    ///
    /// Uses `ergo_primitives::group_element::GroupElement` (opaque newtype
    /// around `[u8; 33]`).
    GroupElement(GroupElement),
    /// Opaque `SigmaProp` value. Platform.scala:45-47.
    SigmaProp(String),
    /// `ProveDlog` (33-byte SEC1-compressed secp256k1 pubkey) -> a REAL,
    /// emittable `SigmaPropConstant(ProveDlog(pk))`, unlike the opaque
    /// [`EnvValue::SigmaProp`] label above. Scala's `keysToEnv`
    /// (`ScriptApiRoute.scala:52-54`) injects each wallet pubkey as
    /// `myPubKey_N -> ProveDlog(pk)` into the `/script/p2sAddress` /
    /// `p2shAddress` compile env; the opaque, non-emittable `SigmaProp(String)`
    /// label (`lib.rs` D-E3) and the raw-curve-point (not SigmaProp-typed)
    /// `GroupElement` variant cannot represent this shape. The downstream
    /// typed-AST/binder/emit plumbing for `ConstPayload::ProveDlog` already
    /// exists end-to-end (the binder's `PK(...)` rule, `binder.rs:604`,
    /// produces the identical shape), so this is the one env-side entry point
    /// that constructs it.
    ProveDlog([u8; 33]),
}

// ── ScriptEnv ─────────────────────────────────────────────────────────────────

/// Ordered compile-time constant environment for the binder.
///
/// A `BTreeMap<String, EnvValue>` wrapper that provides deterministic iteration
/// (alphabetical) and the lookup/membership API used by the binder.
///
/// The env is NOT modified during binder traversal — it is a fixed closure.
/// All Ident occurrences with `NoType` look up the same env snapshot.
#[derive(Debug, Clone, Default)]
pub struct ScriptEnv {
    inner: BTreeMap<String, EnvValue>,
}

impl ScriptEnv {
    /// Create an empty environment.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or overwrite an entry.  Last insertion wins (as in Scala's
    /// immutable `Map` builder).
    pub fn insert(&mut self, key: impl Into<String>, value: EnvValue) {
        self.inner.insert(key.into(), value);
    }

    /// Look up a key; returns `None` when absent.
    pub fn get(&self, key: &str) -> Option<&EnvValue> {
        self.inner.get(key)
    }

    /// Return `true` if `key` is present in the environment.
    pub fn contains(&self, key: &str) -> bool {
        self.inner.contains_key(key)
    }

    /// Iterate over `(key, value)` pairs in alphabetical key order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &EnvValue)> {
        self.inner.iter().map(|(k, v)| (k.as_str(), v))
    }
}

// ── lift ─────────────────────────────────────────────────────────────────────

/// Lift an `EnvValue` to a typed `TypedExpr` constant node.
///
/// Mirrors `SigmaBuilder.liftAny` (SigmaBuilder.scala:219) which calls
/// `Platform.liftToConstant`.  Every `EnvValue` variant lifts successfully;
/// the `Nullable.None` case (unrecognised runtime type) is unreachable here
/// because `EnvValue` only carries liftable types.
///
/// Normative source: Platform.scala:16-65.
///
/// # Deviations (D-T5)
///
/// Every `EnvValue` variant except `GroupElement` lifts unconditionally
/// (matching the Scala doc above). `GroupElement` additionally on-curve-checks
/// the 33-byte key and REJECTS an off-curve or identity (`0x00`-prefix) point
/// (`GroupElementError`). Scala never reaches this case: an env `GroupElement`
/// is always a JVM-constructed curve point (`decodePoint` — the only surface
/// that could produce an off-curve/identity value — is NEVER constant-folded
/// at typecheck time, golden_seed.txt §23(e)), so it has no oracle-observed
/// reject class to mirror byte-for-byte. Rejecting here is a bounded,
/// reject-side-safe deviation from Scala's implicit "cannot happen" invariant
/// (the caller maps this to `BindError::InvalidArguments`, a REAL Scala class
/// used elsewhere in the binder — not a fabricated one).
pub fn lift(v: &EnvValue) -> Result<TypedExpr, GroupElementError> {
    Ok(match v {
        // Platform.scala:37 — Boolean → TrueLeaf / FalseLeaf
        EnvValue::Bool(b) => TypedExpr::Constant {
            value: ConstPayload::Bool(*b),
            tpe: SType::SBoolean,
        },
        // Platform.scala:27 — Byte → ByteConstant
        EnvValue::Byte(n) => TypedExpr::Constant {
            value: ConstPayload::Byte(*n),
            tpe: SType::SByte,
        },
        // Platform.scala:29 — Short → ShortConstant
        EnvValue::Short(n) => TypedExpr::Constant {
            value: ConstPayload::Short(*n),
            tpe: SType::SShort,
        },
        // Platform.scala:31 — Int → IntConstant
        EnvValue::Int(n) => TypedExpr::Constant {
            value: ConstPayload::Int(*n),
            tpe: SType::SInt,
        },
        // Platform.scala:33 — Long → LongConstant
        EnvValue::Long(n) => TypedExpr::Constant {
            value: ConstPayload::Long(*n),
            tpe: SType::SLong,
        },
        // Platform.scala:35 — sigma.BigInt → BigIntConstant; decimal string form
        EnvValue::BigInt(s) => TypedExpr::Constant {
            value: ConstPayload::BigInt(s.clone()),
            tpe: SType::SBigInt,
        },
        // Platform.scala:51-52 — Coll[Byte] / Array[Byte] → ByteArrayConstant
        EnvValue::ByteArray(v) => TypedExpr::Constant {
            value: ConstPayload::ByteColl(v.clone()),
            tpe: SType::SColl(Box::new(SType::SByte)),
        },
        // Platform.scala:55-56 — Coll[Long] / Array[Long] → LongArrayConstant
        EnvValue::LongArray(v) => TypedExpr::Constant {
            value: ConstPayload::LongColl(v.clone()),
            tpe: SType::SColl(Box::new(SType::SLong)),
        },
        // Platform.scala:39-41 — GroupElement → GroupElementConstant.
        // D-T5: on-curve check (rejects off-curve AND identity — see the
        // deviation note above) before storing the bytes-of-record.
        EnvValue::GroupElement(ge) => {
            let bytes = *ge.as_bytes();
            // Discard the decompressed coordinates here — only the on-curve
            // verdict matters at lift time; the printer re-decompresses from
            // the stored bytes on demand (typed_print.rs).
            decompress_to_affine_hex(&bytes)?;
            TypedExpr::Constant {
                value: ConstPayload::GroupElement(bytes),
                tpe: SType::SGroupElement,
            }
        }
        // Platform.scala:45-47 — SigmaProp → SigmaPropConstant (opaque M2)
        EnvValue::SigmaProp(s) => TypedExpr::Constant {
            value: ConstPayload::SigmaProp(s.clone()),
            tpe: SType::SSigmaProp,
        },
        // ScriptApiRoute.scala:52-54 keysToEnv — ProveDlog → a REAL, emittable
        // SigmaPropConstant(ProveDlog(pk)). Same on-curve check as GroupElement
        // above (D-T5 policy: rejects off-curve AND identity), mirroring
        // `binder.rs::bind_pk`'s identical `decompress_to_affine_hex` call —
        // both surfaces produce the exact same `ConstPayload::ProveDlog`
        // shape, so both must reject the same malformed bytes to keep the
        // printer's decompress-on-demand invariant (typed_print.rs) panic-free.
        EnvValue::ProveDlog(pubkey) => {
            decompress_to_affine_hex(pubkey)?;
            TypedExpr::Constant {
                value: ConstPayload::ProveDlog(*pubkey),
                tpe: SType::SSigmaProp,
            }
        }
    })
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::typed_print::print_typed;

    // ----- helpers -----

    fn generator_ge() -> GroupElement {
        // secp256k1 generator point, compressed (parity 02, x-coord follows).
        // Same bytes as g1 in the oracle demo env.
        let mut bytes = [0u8; 33];
        bytes[0] = 0x02;
        let x = hex::decode("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
            .expect("valid hex");
        bytes[1..].copy_from_slice(&x);
        GroupElement::from_bytes(bytes)
    }

    // ----- happy path -----

    #[test]
    fn lift_bool_true_produces_bool_constant() {
        // Platform.scala:37 — Boolean → TrueLeaf
        let v = EnvValue::Bool(true);
        let e = lift(&v).unwrap();
        assert_eq!(
            e,
            TypedExpr::Constant {
                value: ConstPayload::Bool(true),
                tpe: SType::SBoolean,
            }
        );
    }

    #[test]
    fn lift_byte_produces_byte_constant() {
        // Platform.scala:27 — Byte (i8) → ByteConstant
        let v = EnvValue::Byte(-5i8);
        let e = lift(&v).unwrap();
        assert_eq!(
            e,
            TypedExpr::Constant {
                value: ConstPayload::Byte(-5i8),
                tpe: SType::SByte,
            }
        );
    }

    #[test]
    fn lift_short_produces_short_constant() {
        let e = lift(&EnvValue::Short(300i16)).unwrap();
        assert_eq!(
            e,
            TypedExpr::Constant {
                value: ConstPayload::Short(300i16),
                tpe: SType::SShort,
            }
        );
    }

    #[test]
    fn lift_int_produces_int_constant() {
        let e = lift(&EnvValue::Int(42)).unwrap();
        assert_eq!(
            e,
            TypedExpr::Constant {
                value: ConstPayload::Int(42),
                tpe: SType::SInt,
            }
        );
    }

    #[test]
    fn lift_long_produces_long_constant() {
        let e = lift(&EnvValue::Long(1_000_000i64)).unwrap();
        assert_eq!(
            e,
            TypedExpr::Constant {
                value: ConstPayload::Long(1_000_000i64),
                tpe: SType::SLong,
            }
        );
    }

    #[test]
    fn lift_bigint_produces_bigint_constant() {
        // Platform.scala:35 — n1 in demo env is BigInt("5")
        let e = lift(&EnvValue::BigInt("5".to_string())).unwrap();
        assert_eq!(
            e,
            TypedExpr::Constant {
                value: ConstPayload::BigInt("5".to_string()),
                tpe: SType::SBigInt,
            }
        );
        // Verify printer output matches seed §4: `(ConstantNode:BigInt (CBigInt @5))`
        assert_eq!(print_typed(&e), "(ConstantNode:BigInt (CBigInt @5))");
    }

    #[test]
    fn lift_byte_array_produces_bytecoll_constant() {
        // Platform.scala:51-52 — a in demo env is ByteArray([1, 2])
        let e = lift(&EnvValue::ByteArray(vec![1i8, 2i8])).unwrap();
        assert_eq!(
            e,
            TypedExpr::Constant {
                value: ConstPayload::ByteColl(vec![1i8, 2i8]),
                tpe: SType::SColl(Box::new(SType::SByte)),
            }
        );
        // Printer must produce `(ConstantNode:Coll[Byte] <@1 @2>)`
        // matching demo env `a` in golden seed §1.
        assert_eq!(print_typed(&e), "(ConstantNode:Coll[Byte] <@1 @2>)");
    }

    #[test]
    fn lift_long_array_produces_longcoll_constant() {
        // Platform.scala:55-56 — col1 in demo env is LongArray([1, 2])
        let e = lift(&EnvValue::LongArray(vec![1i64, 2i64])).unwrap();
        assert_eq!(
            e,
            TypedExpr::Constant {
                value: ConstPayload::LongColl(vec![1i64, 2i64]),
                tpe: SType::SColl(Box::new(SType::SLong)),
            }
        );
        // Printer must produce `(ConstantNode:Coll[Long] <@1 @2>)`
        // matching col1 in golden seed §4.
        assert_eq!(print_typed(&e), "(ConstantNode:Coll[Long] <@1 @2>)");
    }

    #[test]
    fn lift_group_element_produces_groupelement_constant() {
        // Platform.scala:39-41 — g1 in demo env is the secp256k1 generator.
        let ge = generator_ge();
        let e = lift(&EnvValue::GroupElement(ge)).unwrap();
        assert_eq!(
            e,
            TypedExpr::Constant {
                value: ConstPayload::GroupElement(*ge.as_bytes()),
                tpe: SType::SGroupElement,
            }
        );
        // Printer must decompress to the oracle's affine form (golden_seed.txt L54).
        assert_eq!(
            print_typed(&e),
            "(ConstantNode:GroupElement (CGroupElement (Ecp @(79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8,1))))"
        );
    }

    #[test]
    fn lift_sigma_prop_produces_sigmaprop_constant() {
        let e = lift(&EnvValue::SigmaProp("opaque".to_string())).unwrap();
        assert_eq!(
            e,
            TypedExpr::Constant {
                value: ConstPayload::SigmaProp("opaque".to_string()),
                tpe: SType::SSigmaProp,
            }
        );
    }

    #[test]
    fn lift_prove_dlog_produces_real_sigmaprop_constant() {
        // ScriptApiRoute.scala:52-54 keysToEnv — a wallet pubkey lifts to a
        // REAL, emittable SigmaPropConstant(ProveDlog(pk)), unlike the opaque
        // `SigmaProp(String)` label above.
        let ge = generator_ge();
        let pk = *ge.as_bytes();
        let e = lift(&EnvValue::ProveDlog(pk)).unwrap();
        assert_eq!(
            e,
            TypedExpr::Constant {
                value: ConstPayload::ProveDlog(pk),
                tpe: SType::SSigmaProp,
            }
        );
        // Same decompressed-Ecp printer form as `binder.rs::bind_pk`'s
        // PK("...")-sourced ProveDlog constants (typed_print.rs D-T4) — both
        // surfaces produce the identical shape.
        assert_eq!(
            print_typed(&e),
            "(ConstantNode:SigmaProp (CSigmaProp (ProveDlog (Ecp @(79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8,1)))))"
        );
    }

    // ----- round-trips -----

    #[test]
    fn scriptenv_btree_iteration_is_alphabetical() {
        // BTreeMap guarantees alphabetical key order, which is the
        // "deterministic iteration" requirement from E9.
        let mut env = ScriptEnv::new();
        env.insert("z", EnvValue::Bool(true));
        env.insert("a", EnvValue::Int(1));
        env.insert("m", EnvValue::Long(0));
        let keys: Vec<&str> = env.iter().map(|(k, _)| k).collect();
        assert_eq!(keys, ["a", "m", "z"]);
    }

    #[test]
    fn scriptenv_contains_and_get_reflect_inserts() {
        let mut env = ScriptEnv::new();
        env.insert("HEIGHT", EnvValue::Int(100));
        assert!(env.contains("HEIGHT"));
        assert!(!env.contains("INPUTS"));
        assert_eq!(env.get("HEIGHT"), Some(&EnvValue::Int(100)));
        assert_eq!(env.get("INPUTS"), None);
    }

    #[test]
    fn scriptenv_last_insert_wins() {
        let mut env = ScriptEnv::new();
        env.insert("x", EnvValue::Int(1));
        env.insert("x", EnvValue::Int(2));
        assert_eq!(env.get("x"), Some(&EnvValue::Int(2)));
    }

    // ----- error paths -----

    #[test]
    fn env_value_clone_and_eq() {
        let v = EnvValue::ByteArray(vec![1i8, 2i8, 3i8]);
        assert_eq!(v.clone(), v);
    }

    #[test]
    fn lift_off_curve_group_element_rejects() {
        // D-T5: x=5 has no valid y on secp256k1 (independently verified —
        // see ergo-crypto::group_element::tests::off_curve_bytes).
        let mut bytes = [0u8; 33];
        bytes[0] = 0x02;
        bytes[32] = 0x05;
        let err = lift(&EnvValue::GroupElement(GroupElement::from_bytes(bytes))).unwrap_err();
        assert_eq!(err, GroupElementError::NotOnCurve);
    }

    #[test]
    fn lift_identity_group_element_rejects() {
        // D-T5 identity policy: a 0x00-prefixed literal has no faithful Scala
        // counterpart (env values are always JVM-constructed curve points) —
        // rejected, not accepted as the group identity.
        let bytes = [0u8; 33];
        let err = lift(&EnvValue::GroupElement(GroupElement::from_bytes(bytes))).unwrap_err();
        assert_eq!(err, GroupElementError::Identity);
    }

    #[test]
    fn lift_off_curve_prove_dlog_rejects() {
        // Same D-T5 on-curve check as GroupElement — x=5 has no valid y on
        // secp256k1.
        let mut bytes = [0u8; 33];
        bytes[0] = 0x02;
        bytes[32] = 0x05;
        let err = lift(&EnvValue::ProveDlog(bytes)).unwrap_err();
        assert_eq!(err, GroupElementError::NotOnCurve);
    }

    #[test]
    fn lift_identity_prove_dlog_rejects() {
        // Same D-T5 identity policy as GroupElement.
        let bytes = [0u8; 33];
        let err = lift(&EnvValue::ProveDlog(bytes)).unwrap_err();
        assert_eq!(err, GroupElementError::Identity);
    }
}
