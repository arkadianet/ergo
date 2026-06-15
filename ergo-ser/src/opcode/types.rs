use crate::sigma_type::SigmaType;
use crate::sigma_value::SigmaValue;

/// Maximum byte value that encodes an inline Constant (type code), not an opcode.
pub(super) const LAST_CONSTANT_CODE: u8 = 0x70;

/// Maximum expression-tree depth, matching Scala `SigmaConstants.MaxTreeDepth`
/// (= 110): the reference deserializer increments the shared reader level per
/// nested value and throws `DeserializeCallDepthExceeded` once it exceeds this
/// bound (`CoreByteReader`). A tree nested past 110 levels must be REJECTED to
/// stay consensus-compatible (Scala does not soft-fork this into an
/// `UnparsedErgoTree`), as well as to bound stack use. No real ErgoTree comes
/// close to this depth.
pub(super) const MAX_EXPR_DEPTH: usize = 110;

/// Convenience alias used at the [`crate::ergo_tree`] boundary, where
/// the body of a tree is just a single root [`Expr`].
pub type Body = Expr;

/// A parsed expression node in an ErgoTree body — either an inline
/// constant or an opcode node with a typed payload.
#[derive(Debug, Clone, PartialEq)]
pub enum Expr {
    /// Inline constant: firstByte is a type code (<= 0x70), followed by value data.
    Const { tpe: SigmaType, val: SigmaValue },
    /// Opcode node: firstByte is an opcode (> 0x70), followed by pattern-specific data.
    Op(IrNode),
}

/// One opcode-tagged IR node: the dispatch byte plus the typed payload
/// the parser produced for that opcode's argument pattern.
#[derive(Debug, Clone, PartialEq)]
pub struct IrNode {
    /// Dispatch byte that selected this node's argument pattern.
    pub opcode: u8,
    /// Decoded arguments matching the opcode's expected shape.
    pub payload: Payload,
}

/// Decoded argument payload for an [`IrNode`]. Variants correspond
/// one-for-one to the parser's argument patterns; the simpler `Zero` /
/// `One` / `Two` / `Three` / `Four` cover the bulk of opcodes that take
/// a fixed positional sub-expression list, while the named-field
/// variants carry the structured arguments specific to a given opcode.
#[derive(Debug, Clone, PartialEq)]
pub enum Payload {
    /// No payload — opcode is a leaf (constants, context accessors).
    Zero,
    /// Single sub-expression argument.
    One(Box<Expr>),
    /// Two positional sub-expressions.
    Two(Box<Expr>, Box<Expr>),
    /// Three positional sub-expressions.
    Three(Box<Expr>, Box<Expr>, Box<Expr>),
    /// Four positional sub-expressions (e.g. ProveDHTuple `g, h, u, v`).
    Four(Box<Expr>, Box<Expr>, Box<Expr>, Box<Expr>),
    /// Use of an existing `ValDef`/`FunDef` by binding id.
    ValUse {
        /// Binding id this `ValUse` references.
        id: u32,
    },
    /// Reference to a segregated constant by table index.
    ConstPlaceholder {
        /// Index into the constants table at the tree level.
        index: u32,
    },
    /// Context variable reference with optional declared type.
    TaggedVar {
        /// Variable id (matches `GetVar` / context extension key).
        id: u32,
        /// Declared static type if the parser saw an explicit type tag.
        tpe: Option<SigmaType>,
    },
    /// `val` binding inside a `BlockValue`.
    ValDef {
        /// Binding id used by later `ValUse` references.
        id: u32,
        /// Declared static type, if present.
        tpe: Option<SigmaType>,
        /// Right-hand-side expression bound to `id`.
        rhs: Box<Expr>,
    },
    /// `fun` binding inside a `BlockValue`.
    FunDef {
        /// Binding id used by later `FuncApply` references.
        id: u32,
        /// Declared function type, if present.
        tpe: Option<SigmaType>,
        /// Type-variable parameters of a polymorphic `FunDef`. Scala
        /// `ValDefSerializer` writes `nTpeArgs(u8)` + that many
        /// `STypeVar` types between the id and the rhs for the FunDef
        /// opcode (0xD7) — always present on the wire, possibly empty.
        tpe_args: Vec<SigmaType>,
        /// Function body (typically a `FuncValue`).
        rhs: Box<Expr>,
    },
    /// `{ items; result }` block.
    BlockValue {
        /// `ValDef` / `FunDef` items defined inside the block.
        items: Vec<Expr>,
        /// Block result expression.
        result: Box<Expr>,
    },
    /// Anonymous function literal.
    FuncValue {
        /// Argument list as `(id, optional_type)` pairs.
        args: Vec<(u32, Option<SigmaType>)>,
        /// Function body.
        body: Box<Expr>,
    },
    /// Method dispatch on a sigma-typed receiver.
    MethodCall {
        /// Type id of the receiver's sigma type.
        type_id: u8,
        /// Method id within the receiver's method table.
        method_id: u8,
        /// Receiver expression.
        obj: Box<Expr>,
        /// Method argument list.
        args: Vec<Expr>,
        /// Explicit type arguments that follow the value args on the
        /// wire for v6 methods whose `SMethod.hasExplicitTypeArgs` is
        /// `true` (`SBox.getReg[T]`, `SContext.getVarFromInput[T]`,
        /// `SGlobal.deserializeTo[T]`,
        /// `SGlobal.fromBigEndianBytes[T]`, `SGlobal.some[T]`,
        /// `SGlobal.none[T]`). Empty for every other
        /// method — including the same opcodes on v5 trees, which
        /// dispatch to v5 SMethod variants without explicit type
        /// args. Length is fixed per (type_id, method_id) by
        /// [`method_explicit_type_args_count`].
        type_args: Vec<SigmaType>,
    },
    /// `Coll[T]` literal of a fixed element type.
    ConcreteCollection {
        /// Static element type for every entry.
        elem_type: SigmaType,
        /// Collection items.
        items: Vec<Expr>,
    },
    /// `Coll[Boolean]` packed into bits.
    BoolCollection {
        /// Bit values in collection order.
        bits: Vec<bool>,
    },
    /// Tuple literal (heterogeneous element types).
    Tuple {
        /// Tuple components in declaration order.
        items: Vec<Expr>,
    },
    /// `SelectField` projection on a tuple.
    SelectField {
        /// Tuple-typed input expression.
        input: Box<Expr>,
        /// One-based field index (matches Scala `_1`, `_2`, ...).
        field_idx: u8,
    },
    /// `ExtractRegisterAs` — typed register read on an `SBox`.
    ExtractRegisterAs {
        /// Box-typed input expression.
        input: Box<Expr>,
        /// Register id (`R0`..`R9`; mandatory and additional registers).
        reg_id: u8,
        /// Static type the register is read at.
        tpe: SigmaType,
    },
    /// Context variable read.
    GetVar {
        /// Context variable id (matches the spending proof's extension key).
        var_id: u8,
        /// Static type the variable is read at.
        tpe: SigmaType,
    },
    /// `DeserializeContext` — load a `Coll[Byte]` script from a context var.
    DeserializeContext {
        /// Context variable id supplying the serialized script.
        id: u8,
        /// Static return type of the deserialized expression.
        tpe: SigmaType,
    },
    /// `DeserializeRegister` — load a `Coll[Byte]` script from a register.
    DeserializeRegister {
        /// Register id holding the serialized script bytes.
        reg_id: u8,
        /// Static return type of the deserialized expression.
        tpe: SigmaType,
        /// Optional default expression used if the register is absent.
        default: Option<Box<Expr>>,
    },
    /// Sigma-collection node (used for SigmaAnd / SigmaOr children).
    SigmaCollection {
        /// Children sigma-typed propositions.
        items: Vec<Expr>,
    },
    /// `None: Option[T]` value with a declared static element type.
    NoneValue {
        /// Element type of the option.
        tpe: SigmaType,
    },
    /// `ByIndex` collection access with optional default.
    ByIndex {
        /// Collection-typed input expression.
        input: Box<Expr>,
        /// Index expression (Int-typed).
        index: Box<Expr>,
        /// Optional fallback when the index is out of bounds.
        default: Option<Box<Expr>>,
    },
    /// `Upcast` / `Downcast` numeric type conversion.
    NumericCast {
        /// Source numeric expression.
        input: Box<Expr>,
        /// Target numeric type.
        tpe: SigmaType,
    },
    /// Function application (`func(args...)`).
    FuncApply {
        /// Callee expression.
        func: Box<Expr>,
        /// Positional argument list.
        args: Vec<Expr>,
    },
}

#[derive(Clone, Copy)]
#[allow(dead_code)] // `NoneValue` retained for historical round-trip encoder
                    // parity; dispatch byte 0xDF is no longer parser-accepted.
pub(super) enum ArgPattern {
    Zero,
    One,
    Two,
    Three,
    Four,
    ValUse,
    ConstPlaceholder,
    TaggedVar,
    ValDef,
    FunDef,
    BlockValue,
    FuncValue,
    PropertyCall,
    MethodCall,
    ConcreteCollection,
    BoolCollection,
    CreateTuple,
    SelectField,
    ExtractRegisterAs,
    GetVar,
    DeserializeContext,
    DeserializeRegister,
    SigmaCollection,
    NoneValue,
    ByIndex,
    NumericCast,
    FuncApply,
    /// Relation2Serializer: peekByte==0x85 → read 2 packed bool constants,
    /// otherwise read 2 child expressions normally. Used by all comparison
    /// and boolean binary operators (GT, GE, LT, LE, EQ, NEQ, BinOr, BinAnd, BinXor).
    Relation2,
}

/// Look up the argument pattern for an opcode byte (> LAST_CONSTANT_CODE).
/// Returns `None` for reserved/undefined opcodes.
pub(super) fn opcode_pattern(op: u8) -> Option<ArgPattern> {
    use ArgPattern::*;
    match op {
        0x71 => Some(TaggedVar),
        0x72 => Some(ValUse),
        0x73 => Some(ConstPlaceholder),
        0x74 => Some(Three), // SubstConstants: scriptBytes, positions, newValues

        // 0x75..0x79 reserved
        0x7A => Some(One),         // LongToByteArray
        0x7B => Some(One),         // ByteArrayToBigInt
        0x7C => Some(One),         // ByteArrayToLong
        0x7D => Some(NumericCast), // Downcast
        0x7E => Some(NumericCast), // Upcast

        0x7F => Some(Zero), // True
        0x80 => Some(Zero), // False
        // 0x81 UnitConstant: not in the Scala parser. SUnit flows through
        // constant encoding rather than a dispatch arm.
        0x82 => Some(Zero), // GroupGenerator
        0x83 => Some(ConcreteCollection),
        // 0x84 reserved
        0x85 => Some(BoolCollection),
        0x86 => Some(CreateTuple),
        // 0x87..0x8B Select1..Select5: Scala registers only SelectField
        // (0x8C); Select1-5 have no registered serializer and cannot
        // appear in Scala-accepted bytes.
        0x8C => Some(SelectField),
        // 0x8D..0x8E reserved
        0x8F => Some(Relation2), // Lt
        0x90 => Some(Relation2), // Le
        0x91 => Some(Relation2), // Gt
        0x92 => Some(Relation2), // Ge
        0x93 => Some(Relation2), // Eq
        0x94 => Some(Relation2), // Neq
        0x95 => Some(Three),     // If
        0x96 => Some(One),       // And (logical): single ConcreteCollection arg
        0x97 => Some(One),       // Or (logical): single ConcreteCollection arg
        0x98 => Some(Two),       // AtLeast

        0x99 => Some(Two), // Minus
        0x9A => Some(Two), // Plus
        0x9B => Some(Two), // Xor
        0x9C => Some(Two), // Multiply
        0x9D => Some(Two), // Division
        0x9E => Some(Two), // Modulo
        0x9F => Some(Two), // Exponentiate
        0xA0 => Some(Two), // MultiplyGroup
        0xA1 => Some(Two), // Min
        0xA2 => Some(Two), // Max

        0xA3 => Some(Zero), // Height
        0xA4 => Some(Zero), // Inputs
        0xA5 => Some(Zero), // Outputs
        0xA6 => Some(Zero), // LastBlockUtxoRootHash
        0xA7 => Some(Zero), // Self
        // 0xA8..0xAB reserved
        0xAC => Some(Zero), // MinerPubkey

        0xAD => Some(Two),     // MapCollection
        0xAE => Some(Two),     // Exists
        0xAF => Some(Two),     // ForAll
        0xB0 => Some(Three),   // Fold
        0xB1 => Some(One),     // SizeOf
        0xB2 => Some(ByIndex), // ByIndex (2 required + optional default)
        0xB3 => Some(Two),     // Append
        0xB4 => Some(Three),   // Slice
        0xB5 => Some(Two),     // Filter
        0xB6 => Some(Zero),    // AvlTreeCode (deprecated)
        // 0xB7 TreeLookup — Scala registers QuadrupleSerializer at
        // ValueSerializer.scala:55 with 3 inputs (tree, key, proof) +
        // 1 output type. Wire arity = 3. Scala deserializes OK then
        // rejects at execution via notSupportedError (trees.scala:1336).
        // Our evaluator at evaluator.rs has a reject arm returning
        // EvalError::NotExecutable; same end state. Added to parser
        // for accept-set parity with Scala (was: parser rejected →
        // stricter than Scala, caught by the parity audit below).
        0xB7 => Some(Three), // TreeLookup (deserialize-only; eval rejects)
        // 0xB8 FlatMapCollection: no Scala AST class and no serializer
        // registration in ValueSerializer.scala:42-151. Scala rejects
        // this byte at deserialization via CheckValidOpCode. Falling
        // through to ReadError::InvalidData below matches Scala's
        // rejection.

        // 0xB9..0xC0 reserved
        0xC1 => Some(One), // ExtractAmount
        0xC2 => Some(One), // ExtractScriptBytes
        0xC3 => Some(One), // ExtractBytes
        0xC4 => Some(One), // ExtractBytesWithNoRef
        0xC5 => Some(One), // ExtractId
        0xC6 => Some(ExtractRegisterAs),
        0xC7 => Some(One), // ExtractCreationInfo
        // 0xC8..0xCA reserved
        0xCB => Some(One),  // CalcBlake2b256
        0xCC => Some(One),  // CalcSha256
        0xCD => Some(One),  // ProveDlog
        0xCE => Some(Four), // ProveDHTuple (g, h, u, v)
        0xCF => Some(One),  // SigmaPropIsProven (deprecated but exists)
        0xD0 => Some(One),  // SigmaPropBytes
        0xD1 => Some(One),  // BoolToSigmaProp
        // 0xD2..0xD3 reserved
        0xD4 => Some(DeserializeContext),
        0xD5 => Some(DeserializeRegister),

        0xD6 => Some(ValDef),
        0xD7 => Some(FunDef),
        0xD8 => Some(BlockValue),
        0xD9 => Some(FuncValue),
        0xDA => Some(FuncApply),    // FuncApply
        0xDB => Some(PropertyCall), // PropertyCall (no args)
        0xDC => Some(MethodCall),   // MethodCall
        // 0xDD reserved
        0xDD => Some(Zero), // Global (SGlobal)
        // 0xDE SomeValue: no Scala AST class and no serializer
        // registration; spec appendix (appendix_primops.tex:19) has the
        // row commented out. Scala compiler can't emit it; deserializer
        // rejects it via CheckValidOpCode.
        // 0xDF NoneValue: Scala has no serializer registration;
        // None: Option[T] flows through the
        // constant-encoding path (SOption type + 0x00 discriminant byte).
        // 0xE0..0xE2 reserved
        0xE3 => Some(GetVar),
        0xE4 => Some(One), // OptionGet
        0xE5 => Some(Two), // OptionGetOrElse
        0xE6 => Some(One), // OptionIsDefined

        0xE7 => Some(One), // ModQ (deprecated)
        0xE8 => Some(Two), // PlusModQ
        0xE9 => Some(Two), // MinusModQ

        0xEA => Some(SigmaCollection), // SigmaAnd
        0xEB => Some(SigmaCollection), // SigmaOr

        0xEC => Some(Relation2), // BinOr (lazy)
        0xED => Some(Relation2), // BinAnd (lazy)

        0xEE => Some(One),       // DecodePoint
        0xEF => Some(One),       // LogicalNot
        0xF0 => Some(One),       // Negation
        0xF1 => Some(One),       // BitInversion
        0xF2 => Some(Two),       // BitOr
        0xF3 => Some(Two),       // BitAnd
        0xF4 => Some(Relation2), // BinXor
        0xF5 => Some(Two),       // BitXor
        0xF6 => Some(Two),       // BitShiftRight
        0xF7 => Some(Two),       // BitShiftLeft
        0xF8 => Some(Two),       // BitShiftRightZeroed

        // 0xF9..0xFD reserved
        0xFE => Some(Zero), // Context
        // XorOf is registered with LogicalTransformerSerializer in
        // sigma.serialization.ValueSerializer$ (`new
        // LogicalTransformerSerializer(XorOf$.MODULE$, ...)`),
        // whose `parse` calls `r.getValue()` exactly once and
        // wraps the result in `XorOf(input: Coll[SBoolean])`.
        // Same one-arg shape as And (0x96) and Or (0x97).
        0xFF => Some(One), // XorOf

        _ => None,
    }
}

/// Return the canonical Scala-side name of `op` (e.g. `"ProveDlog"` for
/// `0xCD`, `"???"` for an unrecognized byte). Intended for debug
/// formatting and error messages — not consensus-significant.
pub fn opcode_name(op: u8) -> &'static str {
    match op {
        0x71 => "TaggedVar",
        0x72 => "ValUse",
        0x73 => "ConstPlaceholder",
        0x74 => "SubstConstants",
        0x7A => "LongToByteArray",
        0x7B => "ByteArrayToBigInt",
        0x7C => "ByteArrayToLong",
        0x7D => "Downcast",
        0x7E => "Upcast",
        0x7F => "True",
        0x80 => "False",
        0x81 => "UnitConst",
        0x82 => "GroupGen",
        0x83 => "ConcreteCollection",
        0x85 => "BoolCollection",
        0x86 => "Tuple",
        0x87 => "Select1",
        0x88 => "Select2",
        0x89 => "Select3",
        0x8A => "Select4",
        0x8B => "Select5",
        0x8C => "SelectField",
        0x8F => "Lt",
        0x90 => "Le",
        0x91 => "Gt",
        0x92 => "Ge",
        0x93 => "Eq",
        0x94 => "Neq",
        0x95 => "If",
        0x96 => "And",
        0x97 => "Or",
        0x98 => "AtLeast",
        0x99 => "Minus",
        0x9A => "Plus",
        0x9B => "Xor",
        0x9C => "Multiply",
        0x9D => "Division",
        0x9E => "Modulo",
        0x9F => "Exponentiate",
        0xA0 => "MultiplyGroup",
        0xA1 => "Min",
        0xA2 => "Max",
        0xA3 => "Height",
        0xA4 => "Inputs",
        0xA5 => "Outputs",
        0xA6 => "LastBlockUtxoRootHash",
        0xA7 => "Self",
        0xAC => "MinerPubkey",
        0xAD => "MapCollection",
        0xAE => "Exists",
        0xAF => "ForAll",
        0xB0 => "Fold",
        0xB1 => "SizeOf",
        0xB2 => "ByIndex",
        0xB3 => "Append",
        0xB4 => "Slice",
        0xB5 => "Filter",
        0xB8 => "FlatMap",
        0xC1 => "ExtractAmount",
        0xC2 => "ExtractScriptBytes",
        0xC3 => "ExtractBytes",
        0xC4 => "ExtractBytesNoRef",
        0xC5 => "ExtractId",
        0xC6 => "ExtractRegisterAs",
        0xC7 => "ExtractCreationInfo",
        0xCB => "CalcBlake2b256",
        0xCC => "CalcSha256",
        0xCD => "ProveDlog",
        0xCE => "ProveDHTuple",
        0xCF => "SigmaPropIsProven",
        0xD0 => "SigmaPropBytes",
        0xD1 => "BoolToSigmaProp",
        0xD4 => "DeserializeContext",
        0xD5 => "DeserializeRegister",
        0xD6 => "ValDef",
        0xD7 => "FunDef",
        0xD8 => "BlockValue",
        0xD9 => "FuncValue",
        0xDA => "FuncApply",
        0xDB => "PropertyCall",
        0xDC => "MethodCall",
        0xDD => "Global",
        0xDE => "SomeValue",
        0xDF => "NoneValue",
        0xE3 => "GetVar",
        0xE4 => "OptionGet",
        0xE5 => "OptionGetOrElse",
        0xE6 => "OptionIsDefined",
        0xE7 => "ModQ",
        0xE8 => "PlusModQ",
        0xE9 => "MinusModQ",
        0xEA => "SigmaAnd",
        0xEB => "SigmaOr",
        0xEC => "BinOr",
        0xED => "BinAnd",
        0xEE => "DecodePoint",
        0xEF => "LogicalNot",
        0xF0 => "Negation",
        0xF1 => "BitInversion",
        0xFE => "Context",
        0xFF => "XorOf",
        _ => "???",
    }
}

/// Number of `SType` bytes that follow the value-arg list on the
/// `0xDC MethodCall` wire when `SMethod.hasExplicitTypeArgs` is `true`
/// in the Scala registry. Source: `sigma/ast/methods.scala` on the
/// `v6.0.2` release — every method that sets
/// `hasExplicitTypeArgs = Seq(tT)` (so one type parameter).
///
/// The count is determined purely by `(type_id, method_id)`, NOT by
/// the ErgoTree header's version byte: the Scala 6.0 compiler emits
/// v6 method calls inside v0-header trees (the tree-header version is
/// a wire-format selector, not a script-version selector), so the
/// MethodCall opcode and its explicit-type-args extension are valid
/// payload in any tree version. `[empirical]` Scala-node-extracted
/// vectors pinning this for every pair below:
/// `test-vectors/scala/sigma/v6_methodcall_typeargs_v0_header/`.
///
/// Soft-fork rejection of v6 methods on chains that haven't activated
/// EIP-50 happens at *evaluation* time via `activated_script_version`,
/// not at parse time. Pre-v6 trees can never carry a
/// `(type_id, method_id)` from the list below because those method ids
/// did not exist before 6.0, so reading the type byte is a no-op on
/// legitimate legacy trees.
///
/// Returns `0` when no type bytes follow — covers methods whose
/// `SMethod` does not set the flag and unknown `(type_id, method_id)`
/// pairs.
pub fn method_explicit_type_args_count(type_id: u8, method_id: u8) -> usize {
    // v6 / EIP-50 methods with `hasExplicitTypeArgs = Seq(tT)`.
    // Each carries exactly one `tT` type binding on the wire.
    matches!(
        (type_id, method_id),
        (99, 19)       // SBox.getReg[T]  (v6 id 19; v5 getReg id 7 has none)
            // getVar (101, 11) is getVarV5Method: V5+/commonMethods with
            // NO explicitTypeArgs, so it writes/reads ZERO type bytes
            // (the inline 0xE3 GetVar node carries T, not the MethodCall
            // form). It is intentionally absent here.
            | (101, 12) // SContext.getVarFromInput[T]   (new in v6)
            | (106, 4)  // SGlobal.deserializeTo[T]      (new in v6)
            | (106, 5)  // SGlobal.fromBigEndianBytes[T] (new in v6)
            | (106, 9)  // SGlobal.some[T]               (new in v6)
            | (106, 10) // SGlobal.none[T] (PropertyCall, still carries [T])
    ) as usize
}
