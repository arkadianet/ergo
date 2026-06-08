use ergo_primitives::cost::{CostAccumulator, CostError, CostKind, JitCost};

use super::evaluator::{EvalError, Value};

/// Helper to construct a Fixed cost kind.
const fn fixed(v: u64) -> CostKind {
    CostKind::Fixed(JitCost::from_jit(v))
}

/// Helper to construct a PerItem cost kind.
const fn per_item(base: u64, per_chunk: u64, chunk_size: u32) -> CostKind {
    CostKind::PerItem {
        base: JitCost::from_jit(base),
        per_chunk: JitCost::from_jit(per_chunk),
        chunk_size,
    }
}

/// Returns the `CostKind` for a given opcode, matching Scala's sigmastate-interpreter.
///
/// EQ (0x93) and NEQ (0x94) use dynamic cost — call `add_eq_cost` directly instead.
/// Unknown opcodes return `EvalError::UnsupportedOpcode`. In practice the
/// dispatcher rejects unknown opcodes before they reach this table
/// (`dispatch.rs::eval_expr` catch-all), so a hit here would be a missing
/// cost-row registration for a newly-added executable opcode — a developer
/// bug, surfaced as a typed error so consensus can route it rather than
/// panic.
pub fn opcode_cost(opcode: u8) -> Result<CostKind, EvalError> {
    Ok(match opcode {
        // Values
        0x72 => fixed(5),  // ValUse
        0x73 => fixed(1),  // ConstPlaceholder
        0x7E => fixed(10), // Upcast
        0x7F => fixed(5),  // True
        0x80 => fixed(5),  // False
        0x83 => fixed(20), // ConcreteCollection
        0x86 => fixed(15), // Tuple
        0x8C => fixed(10), // SelectField
        // Select1..Select5 (0x87..0x8B): no cost row by design. Scala
        // registers only SelectField (0x8C); Select1-5 have no
        // serializer registration so they cannot reach the evaluator
        // via real wire bytes. The parser rejects them as well.

        // Comparisons (not EQ/NEQ)
        0x8F => fixed(20), // Lt
        0x90 => fixed(20), // Le
        0x91 => fixed(20), // Gt
        0x92 => fixed(20), // Ge

        // EQ/NEQ — dynamic cost, must be charged via `add_eq_cost` from a
        // type-aware dispatch site, not via this static table. Surface as a
        // typed error so a misrouted caller fails the script cleanly rather
        // than panicking.
        0x93 | 0x94 => {
            return Err(EvalError::RuntimeException(
                "EQ/NEQ opcode routed through opcode_cost; must use add_eq_cost",
            ))
        }

        // Boolean logic
        0x95 => fixed(10),           // If
        0x96 => per_item(10, 5, 32), // AND
        0x97 => per_item(5, 5, 64),  // OR
        0xEC => fixed(20),           // BinOr
        0xED => fixed(20),           // BinAnd

        // Arithmetic
        0x9A => fixed(15), // Plus
        0x99 => fixed(15), // Minus
        0x9C => fixed(15), // Multiply
        0x9D => fixed(15), // Division
        0x9E => fixed(15), // Modulo
        0xA1 => fixed(5),  // Min
        0xA2 => fixed(5),  // Max
        0xF0 => fixed(30), // Negation

        // Context
        0xA3 => fixed(26), // Height
        0xA4 => fixed(10), // Inputs
        0xA5 => fixed(10), // Outputs
        0xA7 => fixed(10), // Self
        0xAC => fixed(20), // MinerPubkey
        0xFE => fixed(1),  // Context
        0xDD => fixed(5),  // Global

        // Box extractors
        0xC1 => fixed(8),  // ExtractAmount
        0xC2 => fixed(10), // ExtractScriptBytes
        0xC5 => fixed(12), // ExtractId
        0xC6 => fixed(50), // ExtractRegisterAs
        0xC7 => fixed(16), // ExtractCreationInfo
        0xC3 => fixed(12), // ExtractBytes
        0xC4 => fixed(12), // ExtractBytesNoRef

        // Collection ops
        0xB1 => fixed(14),            // SizeOf
        0xB2 => fixed(30),            // ByIndex
        0xAD => per_item(20, 1, 10),  // Map
        0xB5 => per_item(20, 1, 10),  // Filter
        0xAE => per_item(3, 1, 10),   // Exists
        0xAF => per_item(3, 1, 10),   // ForAll
        0xB0 => per_item(3, 1, 10),   // Fold
        0xB4 => per_item(10, 2, 100), // Slice
        0xB3 => per_item(20, 2, 100), // Append

        // Option ops
        0xE4 => fixed(15), // OptionGet
        0xE5 => fixed(20), // OptionGetOrElse
        0xE6 => fixed(10), // OptionIsDefined
        // 0xDF NoneValue: no cost row. Scala has no serializer
        // registration for 0xDF; `None: Option[T]` flows through the
        // constant-encoding path. The parser rejects 0xDF.

        // Sigma props
        0xD1 => fixed(15),          // BoolToSigmaProp
        0xCD => fixed(10),          // ProveDlog
        0xCE => fixed(20),          // ProveDHTuple
        0x98 => per_item(10, 2, 1), // AtLeast (k-of-n threshold)
        0xEA => per_item(10, 2, 1), // SigmaAnd
        0xEB => per_item(10, 2, 1), // SigmaOr
        0xD0 => per_item(35, 6, 1), // SigmaPropBytes

        // Crypto/hash
        0xCB => per_item(20, 7, 128), // CalcBlake2b256
        0xCC => per_item(80, 8, 64),  // CalcSha256
        0xEE => fixed(300),           // DecodePoint
        0xFF => per_item(20, 5, 32),  // XorOf

        // SubstConstants
        0x74 => per_item(100, 100, 1), // SubstConstants

        // Control flow / environment
        0xD6 => fixed(5),           // ValDef
        0xD8 => per_item(1, 1, 10), // BlockValue
        0xD9 => fixed(5),           // FuncValue — creation only; AddToEnv(5) charged per call
        0xDA => fixed(30),          // FuncApply
        0xDB => fixed(4),           // PropertyCall
        0xDC => fixed(4),           // MethodCall

        // Context extension
        0xE3 => fixed(10),            // GetVar
        0xD4 => per_item(1, 10, 128), // DeserializeContext
        0xD5 => per_item(1, 10, 128), // DeserializeRegister

        // Type conversions
        0x7A => fixed(17), // LongToByteArray
        0x7C => fixed(16), // ByteArrayToLong
        0x7B => fixed(30), // ByteArrayToBigInt
        0x7D => fixed(10), // Downcast

        // Logical
        0xEF => fixed(15), // LogicalNot — Scala: FixedCost(JitCost::from_jit(15))

        // Group ops
        0x9F => fixed(900), // Exponentiate
        0xA0 => fixed(40),  // MultiplyGroup

        // 0x81 UnitConstant: no cost row. Scala does not register a
        // serializer for 0x81; SUnit values flow through the
        // constant-encoding path. The parser rejects 0x81.

        // ConcreteCollectionBooleanConstant — shares ConcreteCollection.costKind
        // Fixed(20) per Scala values.scala:887-891 (companion delegates to
        // ConcreteCollection at values.scala:878).
        0x85 => fixed(20),

        // GroupGenerator — Scala values.scala:712 FixedCost(JitCost::from_jit(10)).
        0x82 => fixed(10),

        // LastBlockUtxoRootHash — Scala values.scala:1495 FixedCost(JitCost::from_jit(15)).
        0xA6 => fixed(15),

        // BinXor — Scala trees.scala:1300 FixedCost(JitCost::from_jit(20)).
        0xF4 => fixed(20),

        // Xor (byte-array) — Scala trees.scala:1016 PerItemCost(10, 2, 128).
        0x9B => per_item(10, 2, 128),

        // BitOp family (Scala trees.scala:926-941; FixedCost(JitCost::from_jit(1))).
        // Reject-only on the executor (these opcodes are not yet
        // implementable) — cost still accumulates before the eval
        // error so a future flip-to-executable does not change cost
        // accounting.
        0xF2 => fixed(1), // BitOr
        0xF3 => fixed(1), // BitAnd
        0xF5 => fixed(1), // BitXor
        0xF6 => fixed(1), // BitShiftRight
        0xF7 => fixed(1), // BitShiftLeft
        0xF8 => fixed(1), // BitShiftRightZeroed

        _ => return Err(EvalError::UnsupportedOpcode(opcode)),
    })
}

/// Whether the given opcode is an arithmetic primitive `arith_cost` knows
/// about. Centralized so both the non-BigInt and BigInt branches reject
/// non-arithmetic opcodes consistently — otherwise the non-BigInt path
/// would accept anything registered with a Fixed cost (e.g.,
/// ConstPlaceholder 0x73), silently widening the contract.
const fn is_arith_opcode(opcode: u8) -> bool {
    matches!(opcode, 0x99 | 0x9A | 0x9C..=0x9E | 0xA1 | 0xA2)
}

/// Returns the JitCost for an arithmetic opcode, accounting for BigInt's higher cost.
///
/// When `is_bigint` is true, uses the higher TypeBased cost. Otherwise
/// returns the same fixed cost as `opcode_cost`. Non-arithmetic opcodes
/// (anything not in `0x99/0x9A/0x9C–0x9E/0xA1/0xA2`) return
/// `EvalError::UnsupportedOpcode` regardless of `is_bigint`. In practice the
/// arithmetic dispatch arms pass hardcoded literals from that set, so the
/// fallback is unreachable from honest dispatch.
pub fn arith_cost(opcode: u8, is_bigint: bool) -> Result<JitCost, EvalError> {
    if !is_arith_opcode(opcode) {
        return Err(EvalError::UnsupportedOpcode(opcode));
    }
    if !is_bigint {
        match opcode_cost(opcode)? {
            CostKind::Fixed(c) => Ok(c),
            // Arithmetic opcodes are all registered with Fixed costs in
            // `opcode_cost`; a PerItem here would mean someone changed the
            // cost row out from under arith_cost.
            other => Err(EvalError::TypeError {
                expected: "Fixed cost for arithmetic opcode",
                got: format!("{other:?}"),
            }),
        }
    } else {
        Ok(match opcode {
            0x9A | 0x99 => JitCost::from_jit(20), // Plus, Minus
            0x9C..=0x9E => JitCost::from_jit(25), // Multiply, Division, Modulo
            0xA1 | 0xA2 => JitCost::from_jit(10), // Min, Max
            // Unreachable: is_arith_opcode guard above covers this set
            // exhaustively. Surface as a typed error rather than
            // unreachable! so any future expansion of is_arith_opcode that
            // forgets to update this match still fails cleanly.
            _ => return Err(EvalError::UnsupportedOpcode(opcode)),
        })
    }
}

// EQ/NEQ dynamic cost constants (matching Scala's DataValueComparer)
pub(crate) const MATCH_TYPE: u64 = 1;
const EQ_PRIM: u64 = 3;
pub(crate) const EQ_TUPLE: u64 = 4;
const EQ_GROUP_ELEMENT: u64 = 172;
const EQ_BIGINT: u64 = 5;
const EQ_AVL_TREE: u64 = 6;
const EQ_BOX: u64 = 6;
pub(crate) const EQ_OPTION: u64 = 4;
const EQ_PRE_HEADER: u64 = 4;
const EQ_HEADER: u64 = 6;

/// Adds the dynamic cost for EQ/NEQ comparison of a value, matching Scala's
/// `DataValueComparer.equalDataValues`.
///
/// Scala's EQ costs embed the dispatch cost (CasePosition * MatchType) in each
/// type-specific constant. No separate MATCH_TYPE is charged at the top level
/// for primitives — EQ_Prim(3) already includes dispatch(1) + operation(2).
/// Collections charge an explicit MatchType for the inner type dispatch.
/// `colls_match_len`: for collection types, whether both operands have the
/// same length. Scala short-circuits (charges only MatchType) when they differ.
pub fn add_eq_cost(
    cost: &mut CostAccumulator,
    value: &Value,
    colls_match_len: bool,
) -> Result<(), CostError> {
    match value {
        // Case 1: primitives — EQ_Prim(3) includes dispatch
        Value::Bool(_) | Value::Byte(_) | Value::Short(_) | Value::Int(_) | Value::Long(_) => {
            cost.add(JitCost::from_jit(EQ_PRIM))
        }
        // Unit — cheap equality; Scala charges a single EQ_Prim for it
        Value::Unit => cost.add(JitCost::from_jit(EQ_PRIM)),
        Value::BigInt(_) | Value::UnsignedBigInt(_) => cost.add(JitCost::from_jit(EQ_BIGINT)),
        // Case 4: group element — cost includes dispatch
        Value::GroupElement(_) => cost.add(JitCost::from_jit(EQ_GROUP_ELEMENT)),
        Value::SigmaProp(_) => {
            cost.add(JitCost::from_jit(MATCH_TYPE))?;
            cost.add(JitCost::from_jit(EQ_GROUP_ELEMENT))
        }
        Value::Tuple(elems) => {
            cost.add(JitCost::from_jit(EQ_TUPLE))?;
            for elem in elems {
                add_eq_cost(cost, elem, true)?;
            }
            Ok(())
        }
        // Boxed-element coll carrier (Coll[Tuple], Coll[Header]
        // fallback, etc.). Charged identically to a real Tuple of
        // the same arity — both walk element-wise EQ. A Scala-anchored
        // per-element-coll cost would refine this, but parity with
        // the pre-disambiguation behavior is the carrier-refactor
        // goal: no observable cost drift.
        Value::CollGeneric(elems, _) => {
            cost.add(JitCost::from_jit(EQ_TUPLE))?;
            for elem in elems {
                add_eq_cost(cost, elem, true)?;
            }
            Ok(())
        }
        Value::Opt(inner) => {
            cost.add(JitCost::from_jit(EQ_OPTION))?;
            if let Some(v) = inner {
                add_eq_cost(cost, v, true)?;
            }
            Ok(())
        }
        Value::PreHeader => cost.add(JitCost::from_jit(EQ_PRE_HEADER)),

        // Box-like values
        Value::SelfBox | Value::BoxRef { .. } | Value::InlineBox(_) => {
            cost.add(JitCost::from_jit(EQ_BOX))
        }

        // Collection comparisons: Scala's equalDataValues charges MatchType(1)
        // for the collection dispatch (case 2). equalColls_Dispatch dispatches
        // on tItem without explicit MatchType — only 1 MatchType total.
        Value::CollBool(v) => {
            cost.add(JitCost::from_jit(MATCH_TYPE))?;
            if colls_match_len {
                cost.add_per_item(per_item(15, 2, 128), v.len() as u32)?;
            }
            Ok(())
        }
        Value::CollBytes(v) => {
            cost.add(JitCost::from_jit(MATCH_TYPE))?;
            if colls_match_len {
                cost.add_per_item(per_item(15, 2, 128), v.len() as u32)?;
            }
            Ok(())
        }
        // SString EQ mirrors the pre-carrier Coll[Byte] cost (strings were
        // lowered to Coll[Byte] before the Value::Str carrier), so EQ
        // behavior is unchanged; only SGlobal.serialize uses SString's
        // cheaper length cost.
        Value::Str(s) => {
            cost.add(JitCost::from_jit(MATCH_TYPE))?;
            if colls_match_len {
                cost.add_per_item(per_item(15, 2, 128), s.len() as u32)?;
            }
            Ok(())
        }
        Value::CollInt(v) => {
            cost.add(JitCost::from_jit(MATCH_TYPE))?;
            if colls_match_len {
                cost.add_per_item(per_item(15, 2, 64), v.len() as u32)?;
            }
            Ok(())
        }
        Value::CollLong(v) => {
            cost.add(JitCost::from_jit(MATCH_TYPE))?;
            if colls_match_len {
                cost.add_per_item(per_item(15, 2, 48), v.len() as u32)?;
            }
            Ok(())
        }
        Value::CollShort(v) => {
            // Coll[Short]: 16-bit elements — chunk size between bytes (128) and ints (64).
            cost.add(JitCost::from_jit(MATCH_TYPE))?;
            if colls_match_len {
                cost.add_per_item(per_item(15, 2, 96), v.len() as u32)?;
            }
            Ok(())
        }
        Value::CollSigmaProp(v) => {
            cost.add(JitCost::from_jit(MATCH_TYPE))?;
            if colls_match_len {
                cost.add_per_item(per_item(15, 5, 1), v.len() as u32)?;
            }
            Ok(())
        }
        Value::Tokens(v) => {
            // Scala equalDataValues: MatchType for collection dispatch, then
            // equalColls_Dispatch: MatchType + PerItem(10,2,1) for SAny.
            // Per element: EQ_Tuple, then recursive equalDataValues for each
            // field — Coll[Byte] gets MatchType+MatchType+PerItem, Long gets EQ_Prim.
            cost.add(JitCost::from_jit(MATCH_TYPE))?;
            if colls_match_len {
                cost.add(JitCost::from_jit(MATCH_TYPE))?;
                cost.add_per_item(per_item(10, 2, 1), v.len() as u32)?;
                for _ in v {
                    cost.add(JitCost::from_jit(EQ_TUPLE))?;
                    // token_id: Coll[Byte] 32 bytes — two MatchTypes (collection + type dispatch)
                    cost.add(JitCost::from_jit(MATCH_TYPE))?;
                    cost.add(JitCost::from_jit(MATCH_TYPE))?;
                    cost.add_per_item(per_item(15, 2, 128), 32)?;
                    // amount: Long — just EQ_Prim (dispatch cost embedded)
                    cost.add(JitCost::from_jit(EQ_PRIM))?;
                }
            }
            Ok(())
        }

        // CollBox — typed Coll[Box], collection dispatch + EQ_COA_Box PerItemCost
        Value::CollBox(elems) => {
            cost.add(JitCost::from_jit(MATCH_TYPE))?;
            if colls_match_len {
                cost.add_per_item(per_item(15, 5, 1), elems.len() as u32)?;
            }
            Ok(())
        }
        // BoxCollection — length unknown in cost_table (needs context).
        // The evaluator wrapper (add_eq_neq_cost) handles this case.
        Value::BoxCollection(_) => cost.add(JitCost::from_jit(EQ_BOX)),
        Value::Global => cost.add(JitCost::from_jit(EQ_PRIM)),

        Value::AvlTree(_) => cost.add(JitCost::from_jit(EQ_AVL_TREE)),

        // Header — single header comparison
        Value::Header(_) => cost.add(JitCost::from_jit(EQ_HEADER)),
        // CollHeader — collection of headers
        Value::CollHeader(v) => {
            cost.add(JitCost::from_jit(MATCH_TYPE))?;
            if colls_match_len {
                cost.add_per_item(per_item(15, 5, 1), v.len() as u32)?;
            }
            Ok(())
        }

        // Functions are not comparable in Ergo
        Value::Func { .. } => cost.add(JitCost::from_jit(EQ_PRIM)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_primitives::cost::{CostAccumulator, CostKind, JitCost};

    #[test]
    fn height_opcode_cost() {
        match opcode_cost(0xA3).expect("0xA3 is registered") {
            CostKind::Fixed(c) => assert_eq!(c, JitCost::from_jit(26)),
            other => panic!("expected Fixed, got {:?}", other),
        }
    }

    #[test]
    fn calc_blake2b256_per_item() {
        match opcode_cost(0xCB).expect("0xCB is registered") {
            CostKind::PerItem {
                base,
                per_chunk,
                chunk_size,
            } => {
                assert_eq!(base, JitCost::from_jit(20));
                assert_eq!(per_chunk, JitCost::from_jit(7));
                assert_eq!(chunk_size, 128);
            }
            other => panic!("expected PerItem, got {:?}", other),
        }
    }

    #[test]
    fn unknown_opcode_returns_typed_error() {
        let err = opcode_cost(0x00).expect_err("0x00 has no cost row");
        assert!(
            matches!(err, EvalError::UnsupportedOpcode(0x00)),
            "expected UnsupportedOpcode(0x00), got {err:?}"
        );
    }

    #[test]
    fn arith_cost_bigint_vs_normal() {
        // Non-BigInt Plus: 15
        assert_eq!(arith_cost(0x9A, false).unwrap(), JitCost::from_jit(15));
        // BigInt Plus: 20
        assert_eq!(arith_cost(0x9A, true).unwrap(), JitCost::from_jit(20));
        // Non-BigInt Multiply: 15
        assert_eq!(arith_cost(0x9C, false).unwrap(), JitCost::from_jit(15));
        // BigInt Multiply: 25
        assert_eq!(arith_cost(0x9C, true).unwrap(), JitCost::from_jit(25));
        // Non-BigInt Min: 5
        assert_eq!(arith_cost(0xA1, false).unwrap(), JitCost::from_jit(5));
        // BigInt Min: 10
        assert_eq!(arith_cost(0xA1, true).unwrap(), JitCost::from_jit(10));
    }

    #[test]
    fn arith_cost_unknown_opcode_returns_typed_error() {
        let err = arith_cost(0x00, true).expect_err("0x00 is not arithmetic");
        assert!(
            matches!(err, EvalError::UnsupportedOpcode(0x00)),
            "expected UnsupportedOpcode(0x00) on BigInt path, got {err:?}"
        );
        let err = arith_cost(0x00, false).expect_err("0x00 is not arithmetic");
        assert!(
            matches!(err, EvalError::UnsupportedOpcode(0x00)),
            "expected UnsupportedOpcode(0x00) on non-BigInt path, got {err:?}"
        );
    }

    #[test]
    fn arith_cost_rejects_registered_non_arith_opcode_on_non_bigint_path() {
        // Regression: pre-fix, arith_cost(non_arith, false) delegated to
        // opcode_cost and returned the Fixed cost for any registered
        // opcode (e.g. ConstPlaceholder 0x73 -> Fixed(1)), silently
        // widening the contract beyond the arithmetic set.
        for op in [0x73u8, 0xA3, 0xCB] {
            let err = arith_cost(op, false)
                .expect_err("registered-but-non-arithmetic opcode must reject on non-BigInt path");
            assert!(
                matches!(err, EvalError::UnsupportedOpcode(o) if o == op),
                "expected UnsupportedOpcode(0x{op:02X}), got {err:?}"
            );
        }
    }

    #[test]
    fn eq_cost_int() {
        let mut acc = CostAccumulator::recording_only();
        add_eq_cost(&mut acc, &Value::Int(42), true).unwrap();
        // EQ_PRIM(3) — includes dispatch cost
        assert_eq!(acc.total(), JitCost::from_jit(3));
    }

    #[test]
    fn eq_cost_tuple_of_ints() {
        let mut acc = CostAccumulator::recording_only();
        let val = Value::Tuple(vec![Value::Int(1), Value::Long(2)]);
        add_eq_cost(&mut acc, &val, true).unwrap();
        // EQ_TUPLE(4) + EQ_PRIM(3) * 2 = 10
        assert_eq!(acc.total(), JitCost::from_jit(10));
    }

    #[test]
    fn eq_cost_option_some() {
        let mut acc = CostAccumulator::recording_only();
        let val = Value::Opt(Some(Box::new(Value::Bool(true))));
        add_eq_cost(&mut acc, &val, true).unwrap();
        // EQ_OPTION(4) + EQ_PRIM(3) = 7
        assert_eq!(acc.total(), JitCost::from_jit(7));
    }

    #[test]
    fn eq_cost_option_none() {
        let mut acc = CostAccumulator::recording_only();
        let val = Value::Opt(None);
        add_eq_cost(&mut acc, &val, true).unwrap();
        // EQ_OPTION(4)
        assert_eq!(acc.total(), JitCost::from_jit(4));
    }

    #[test]
    fn eq_cost_coll_bytes() {
        let mut acc = CostAccumulator::recording_only();
        let val = Value::CollBytes(vec![0u8; 256]);
        add_eq_cost(&mut acc, &val, true).unwrap();
        // 1×MATCH_TYPE(1) + PerItem(15, 2, 128).compute(256)
        // chunks = (256-1)/128 + 1 = 2
        // per_item_cost = 15 + 2*2 = 19
        // total = 1 + 19 = 20
        assert_eq!(acc.total(), JitCost::from_jit(20));
    }

    #[test]
    fn eq_cost_group_element() {
        let mut acc = CostAccumulator::recording_only();
        let val = Value::GroupElement([0u8; 33]);
        add_eq_cost(&mut acc, &val, true).unwrap();
        // EQ_GROUP_ELEMENT(172) — includes dispatch cost
        assert_eq!(acc.total(), JitCost::from_jit(172));
    }

    #[test]
    fn eq_neq_opcode_returns_typed_error() {
        for op in [0x93u8, 0x94] {
            let err = opcode_cost(op).expect_err(
                "EQ/NEQ opcodes must error: they require dynamic dispatch via add_eq_cost",
            );
            assert!(
                matches!(
                    err,
                    EvalError::RuntimeException(msg)
                        if msg.contains("EQ/NEQ") && msg.contains("add_eq_cost"),
                ),
                "expected RuntimeException pointing callers at add_eq_cost for opcode 0x{op:02X}, got {err:?}"
            );
        }
    }
}
