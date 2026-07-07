//! Parser-domain SType: types as the parser sees them.
//!
//! This module defines the SType enum, deliberately distinct from ergo-ser's
//! SigmaType. The parser needs `NoType` and `STypeApply` variants that
//! ergo-ser's SigmaType lacks.
//! Cites: Types.scala:30-49 (predef table), SType.scala:105-122 + :338 (gate).

/// Parser-domain type representation.
///
/// Includes primitive types, compound shapes (SColl/SOption/STuple/SFunc),
/// compiler-internal types (STypeVar/STypeApply), and NoType (eliminated by
/// the typer). See [`is_predef_available`] for version-gating.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SType {
    /// Eliminated by the typer (SType.scala:278-281).
    NoType,
    /// Primitive types: v5 core set.
    SBoolean,
    SByte,
    SShort,
    SInt,
    SLong,
    SBigInt,
    /// Added in v3+ (SType.scala:105-122).
    SUnsignedBigInt,
    SGroupElement,
    SSigmaProp,
    SAvlTree,
    SContext,
    SGlobal,
    SHeader,
    SPreHeader,
    SString,
    SBox,
    SUnit,
    SAny,
    /// Unknown bare name (Types.scala:129).
    STypeVar(String),
    /// Collection type.
    SColl(Box<SType>),
    /// Optional type.
    SOption(Box<SType>),
    /// Tuple type (heterogeneous).
    STuple(Vec<SType>),
    /// Function type: domain → range.
    ///
    /// `tpe_params` carries the polymorphic type-parameter idents (`STypeParam.ident`,
    /// SType.scala:78-89) so an *unapplied* polymorphic method/predef value prints its
    /// `[T]`/`[K,L,R,O]` binder (SType.scala:644,653 `toTermString`).  It is EMPTY for
    /// every monomorphic function type — lambdas, applied methods, and the parser's
    /// function-type syntax all build `tpe_params: vec![]`; only the predef env
    /// (`predef_ir::predefined_env`) and the bare-method Select path
    /// (`typer::assign::assign_select`) populate it.  Method *descriptors* carry their
    /// params in [`crate::typer::unify::SFuncSpec`]; this slot mirrors them onto the
    /// printed node type.
    SFunc {
        dom: Vec<SType>,
        range: Box<SType>,
        tpe_params: Vec<String>,
    },
    /// Compiler-IR-only type application (SType.scala:695-704).
    STypeApply {
        name: String,
        args: Vec<SType>,
    },
}

/// Resolve a predefined type name to its SType.
///
/// Returns the type for any of the 18 predefined names in the compiler's table
/// (Types.scala:30-49):
/// - v5 (17 types): SBoolean, SByte, SShort, SInt, SLong, SBigInt, SContext,
///   SGlobal, SHeader, SPreHeader, SAvlTree, SGroupElement, SSigmaProp, SString,
///   SBox, SUnit, SAny.
/// - v3+ (1 type): SUnsignedBigInt.
///
/// Structural types (SColl, SOption, STuple, SFunc) are NOT in the table.
/// Unknown names return None.
pub fn predef_type(name: &str) -> Option<SType> {
    match name {
        "Boolean" => Some(SType::SBoolean),
        "Byte" => Some(SType::SByte),
        "Short" => Some(SType::SShort),
        "Int" => Some(SType::SInt),
        "Long" => Some(SType::SLong),
        "BigInt" => Some(SType::SBigInt),
        "UnsignedBigInt" => Some(SType::SUnsignedBigInt),
        "AvlTree" => Some(SType::SAvlTree),
        "Context" => Some(SType::SContext),
        "GroupElement" => Some(SType::SGroupElement),
        "SigmaProp" => Some(SType::SSigmaProp),
        "Global" => Some(SType::SGlobal),
        "Header" => Some(SType::SHeader),
        "PreHeader" => Some(SType::SPreHeader),
        "String" => Some(SType::SString),
        "Box" => Some(SType::SBox),
        "Unit" => Some(SType::SUnit),
        "Any" => Some(SType::SAny),
        _ => None,
    }
}

/// Check if a type is available in the given ergo tree version.
///
/// Mirrors SType.scala:105-122 availability gate:
/// - All 17 v5 primitive types are available at every version (0+).
/// - SUnsignedBigInt is available only at tree_version >= 3.
/// - Compound shapes (SColl, SOption, STuple, SFunc), STypeVar, STypeApply,
///   and NoType are never "predef available" (checked by SPrimType.unapply in
///   Scala — they are not in the predefined-type table).
pub fn is_predef_available(t: &SType, tree_version: u8) -> bool {
    match t {
        // v5 core: available at all versions.
        SType::SBoolean
        | SType::SByte
        | SType::SShort
        | SType::SInt
        | SType::SLong
        | SType::SBigInt
        | SType::SContext
        | SType::SGlobal
        | SType::SHeader
        | SType::SPreHeader
        | SType::SAvlTree
        | SType::SGroupElement
        | SType::SSigmaProp
        | SType::SString
        | SType::SBox
        | SType::SUnit
        | SType::SAny => true,

        // v3+ only.
        SType::SUnsignedBigInt => tree_version >= 3,

        // Non-predef shapes are never available.
        SType::NoType
        | SType::STypeVar(_)
        | SType::SColl(_)
        | SType::SOption(_)
        | SType::STuple(_)
        | SType::SFunc { .. }
        | SType::STypeApply { .. } => false, // SFunc: never predef-available regardless of tpe_params
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- happy path -----

    #[test]
    fn predef_type_all_18_names_resolve() {
        // Types.scala:30-49, verbatim table.
        for (name, t) in [
            ("Boolean", SType::SBoolean),
            ("Byte", SType::SByte),
            ("Short", SType::SShort),
            ("Int", SType::SInt),
            ("Long", SType::SLong),
            ("BigInt", SType::SBigInt),
            ("UnsignedBigInt", SType::SUnsignedBigInt),
            ("AvlTree", SType::SAvlTree),
            ("Context", SType::SContext),
            ("GroupElement", SType::SGroupElement),
            ("SigmaProp", SType::SSigmaProp),
            ("Global", SType::SGlobal),
            ("Header", SType::SHeader),
            ("PreHeader", SType::SPreHeader),
            ("String", SType::SString),
            ("Box", SType::SBox),
            ("Unit", SType::SUnit),
            ("Any", SType::SAny),
        ] {
            assert_eq!(predef_type(name), Some(t), "{name}");
        }
    }

    #[test]
    fn predef_type_unknown_and_structural_names_none() {
        // Coll/Option are structural (Types.scala:126-127), not in the table.
        for name in ["Coll", "Option", "Foo", "int", ""] {
            assert_eq!(predef_type(name), None, "{name}");
        }
    }

    // ----- error paths -----

    #[test]
    fn is_predef_available_gates_unsignedbigint_below_v3() {
        // SType.scala:105-122: v6 predef set = v5 + SUnsignedBigInt only.
        assert!(!is_predef_available(&SType::SUnsignedBigInt, 0));
        assert!(!is_predef_available(&SType::SUnsignedBigInt, 2));
        assert!(is_predef_available(&SType::SUnsignedBigInt, 3));
        // Every v5 member is available at every version.
        assert!(is_predef_available(&SType::SString, 0));
        assert!(is_predef_available(&SType::SBox, 0));
        // Non-predef shapes are never "predef available" (SPrimType.unapply misses).
        assert!(!is_predef_available(&SType::NoType, 3));
        assert!(!is_predef_available(
            &SType::SColl(Box::new(SType::SInt)),
            3
        ));
    }
}
