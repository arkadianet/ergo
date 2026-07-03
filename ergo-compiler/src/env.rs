//! ScriptEnv — compile-time constant substitution environment for the binder.
//!
//! Mirrors `sigmastate.interpreter.Interpreter.ScriptEnv` (Scala `Map[String, Any]`,
//! Interpreter.scala:503), restricted to the value types that
//! `Platform.liftToConstant` (data/jvm/src/main/scala/sigma/Platform.scala:16-65)
//! successfully lifts and that appear in the oracle demo env (m2-typer-plan.md E9).
//!
//! Uses `BTreeMap` for deterministic iteration order (alphabetical by key).

use std::collections::BTreeMap;

use ergo_primitives::group_element::GroupElement;

use crate::stype::SType;
use crate::typed::{ConstPayload, TypedExpr};

// ── EnvValue ─────────────────────────────────────────────────────────────────

/// A single compile-time constant value in the script environment.
///
/// Covers every value type that `Platform.liftToConstant` handles and that
/// appears in the oracle demo env (E9).  The version-gated arms
/// (java.math.BigInteger at v5 only, sigma.Header/PreHeader/UnsignedBigInt at
/// v6 only) are omitted — they are not reachable from the demo env and the
/// oracle does not exercise them in M2 scope.
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
    /// Opaque `SigmaProp` value (M3 scope for full parity). Platform.scala:45-47.
    SigmaProp(String),
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
/// # Deviations (M2)
///
/// `GroupElement` renders the 33-byte key as a hex string in
/// `ConstPayload::GroupElement`.  M3 must replace this with the Scala
/// `Ecp.toString` decompressed form `(x_hex,y_hex,1)`.
pub fn lift(v: &EnvValue) -> TypedExpr {
    match v {
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
        // deviation: M2 renders the 33-byte key as hex rather than the Scala
        // Ecp.toString `(x_hex,y_hex,1)` form (requires curve decompression).
        // M3: replace with proper decompressed rendering.
        EnvValue::GroupElement(ge) => {
            let hex: String = ge.as_bytes().iter().map(|b| format!("{:02x}", b)).collect();
            TypedExpr::Constant {
                value: ConstPayload::GroupElement(hex),
                tpe: SType::SGroupElement,
            }
        }
        // Platform.scala:45-47 — SigmaProp → SigmaPropConstant (opaque M2)
        EnvValue::SigmaProp(s) => TypedExpr::Constant {
            value: ConstPayload::SigmaProp(s.clone()),
            tpe: SType::SSigmaProp,
        },
    }
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
        let e = lift(&v);
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
        let e = lift(&v);
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
        let e = lift(&EnvValue::Short(300i16));
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
        let e = lift(&EnvValue::Int(42));
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
        let e = lift(&EnvValue::Long(1_000_000i64));
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
        let e = lift(&EnvValue::BigInt("5".to_string()));
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
        let e = lift(&EnvValue::ByteArray(vec![1i8, 2i8]));
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
        let e = lift(&EnvValue::LongArray(vec![1i64, 2i64]));
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
        let e = lift(&EnvValue::GroupElement(ge));
        // Type must be SGroupElement.
        assert!(matches!(
            e,
            TypedExpr::Constant {
                value: ConstPayload::GroupElement(_),
                tpe: SType::SGroupElement,
            }
        ));
    }

    #[test]
    fn lift_sigma_prop_produces_sigmaprop_constant() {
        let e = lift(&EnvValue::SigmaProp("opaque".to_string()));
        assert_eq!(
            e,
            TypedExpr::Constant {
                value: ConstPayload::SigmaProp("opaque".to_string()),
                tpe: SType::SSigmaProp,
            }
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
}
