//! Typed ErgoScript AST — mirrors the sigma-state 6.0.2 typed vocabulary.
//!
//! This module defines `TypedExpr`, the Rust twin of the Scala typed-tree that
//! `SigmaTyper.typecheck` produces (with `TransformingSigmaBuilder`,
//! `lowerMethodCalls=true`). Every variant mirrors the Scala case class
//! constructor ORDER because the canonical s-expression printer (typed_print.rs)
//! renders fields positionally via `productIterator` parity.
//!
//! Normative Scala source:
//!   values.scala    — Block/ValNode/Ident/Lambda/Select/Apply/Tuple/Constant/…
//!   trees.scala     — ArithOp/BitOp/relations/bool-ops/group-ops/hash/…
//!   transformers.rs — MapCollection/Filter/Exists/ForAll/Fold/ByIndex/OptionGet/…
//! All under sigmastate-interpreter-v6.0.2/ (pinned 6.0.2 worktree).
//!
//! Design decisions encoded here:
//! - `tpe: SType` on every variant — used by the printer for the `:TypeTermString`
//!   annotation and for N2 normalization (skip SType fields that equal the node's
//!   own type). It is NOT a rendered field itself.
//! - `Self_` (not `Self`) to avoid the Rust keyword; product_prefix returns "Self".
//! - `MethodCall` carries `type_subst: Vec<(String, SType)>` (sorted by the printer
//!   per N4); `Vec` not `HashMap` for determinism.
//! - Lambda `args: Vec<(String, SType)>` — (name, type) pairs rendered as `name:#Type`.
//! - `STypeParam { ident: String }` — simplified (only ident needed for printing;
//!   upper/lower bounds always NoType for well-formed M2 lambdas).
//! - `ConstPayload` covers all literal types in the oracle demo env and common
//!   script constants.

use crate::stype::SType;

/// A single type parameter ident for Lambda.tpe_params.
///
/// Scala: `case class STypeParam(ident: STypeVar, upperBound: SType, lowerBound: SType)`
/// (SType.scala:78-89). For M2, tpeParams are always empty on well-formed Lambdas
/// (binder enforces `require(!(tpeParams.nonEmpty && body.nonEmpty))`); the field
/// exists for structural completeness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct STypeParam {
    pub ident: String,
}

/// Method reference for MethodCall — printed as `%Owner.name`.
///
/// Mirrors `SMethod.objType.typeName + "." + method.name` (methods.scala:44,52).
/// Owner is the TYPE NAME of the receiver (e.g. "SigmaDslBuilder" for SGlobal,
/// "SCollection" for SColl, "GroupElement" for SGroupElement, "BigInt" for SBigInt,
/// "AvlTree" for SAvlTree).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MethodRef {
    pub owner: String,
    pub name: String,
}

/// Constant payload for M2 scope — all literal types reachable in the oracle demo
/// environment and common script expressions.
///
/// Rendering (typed_print.rs `render_payload`):
///   Bool(b)                 → `@true` / `@false`
///   Byte(n)                 → `@n` (signed decimal)
///   Short(n)                → `@n`
///   Int(n)                  → `@n`
///   Long(n)                 → `@n`
///   BigInt(s)               → `(CBigInt @s)` where s is the decimal string
///   Unit                    → (no value field — ConstantNode:Unit renders with no value)
///   ByteColl(v)             → `<@v1 @v2 …>` decimal signed bytes, space-sep
///   LongColl(v)             → `<@v1 @v2 …>` decimal longs, space-sep
///   GroupElement(ecp_str)   → `(CGroupElement (Ecp @ecp_str))` where ecp_str is the
///                             Ecp toString from Scala (e.g. "(x_hex,y_hex,1)").
///                             M2 scope: caller must supply the correct JVM-format string.
///   SigmaProp(inner_str)    → opaque rendering (M3 scope for full parity)
#[derive(Debug, Clone, PartialEq)]
pub enum ConstPayload {
    /// `@true` or `@false` — values.scala TrueLeaf/FalseLeaf, BooleanConstant.
    Bool(bool),
    /// `@n` signed decimal — ByteConstant (values.scala:445).
    Byte(i8),
    /// `@n` signed decimal — ShortConstant (values.scala:451).
    Short(i16),
    /// `@n` signed decimal — IntConstant (values.scala:458).
    Int(i32),
    /// `@n` signed decimal — LongConstant (values.scala:466).
    Long(i64),
    /// `(CBigInt @n)` — BigIntConstant (values.scala:476); n is decimal.
    BigInt(String),
    /// No value rendered — UnitConstant (values.scala:497).
    Unit,
    /// `<@v1 @v2 …>` — ByteArrayConstant elements (values.scala:507).
    ByteColl(Vec<i8>),
    /// `<@v1 @v2 …>` — LongArrayConstant elements (values.scala:511).
    LongColl(Vec<i64>),
    /// `(CGroupElement (Ecp @ecp_str))` — GroupElementConstant (values.scala:519).
    /// ecp_str is the Scala Ecp.toString form, e.g. "(x,y,1)".
    GroupElement(String),
    /// Opaque SigmaProp payload (M3 scope for full parity).
    SigmaProp(String),
}

/// Typed ErgoScript AST node.
///
/// Mirrors the Scala typed vocabulary 1:1 (oracle R6). Every variant corresponds
/// to a Scala case class or case object; the `productPrefix` returned by
/// `typed_print::product_prefix` must match Scala's runtime `productPrefix`.
///
/// Field order within each variant = Scala constructor parameter order
/// (productIterator order), which is what the printer renders positionally.
/// The `tpe` field records the node's assigned type for annotation + N2 and is
/// NOT itself a printed field.
#[derive(Debug, Clone, PartialEq)]
pub enum TypedExpr {
    // ── context singletons (values.scala) ────────────────────────────────────
    // case object Height/Self/… — no payload fields beyond the node type.
    /// `HEIGHT` — values.scala:1456 Height: SInt.
    Height { tpe: SType },
    /// `SELF` — values.scala:1471 Self: SBox.
    /// Rust name `Self_` avoids the reserved keyword; productPrefix = "Self".
    Self_ { tpe: SType },
    /// `INPUTS` — values.scala:1480 Inputs: SColl[SBox].
    Inputs { tpe: SType },
    /// `OUTPUTS` — values.scala:1484 Outputs: SColl[SBox].
    Outputs { tpe: SType },
    /// `CONTEXT` — values.scala:1447 Context: SContext.
    Context { tpe: SType },
    /// `Global` — values.scala:1415 Global: SGlobal (prints as SigmaDslBuilder).
    Global { tpe: SType },
    /// `MinerPubkey` — values.scala:1436 MinerPubkey: SColl[SByte].
    MinerPubkey { tpe: SType },
    /// `LastBlockUtxoRootHash` — values.scala:1490 LastBlockUtxoRootHash: SAvlTree.
    LastBlockUtxoRootHash { tpe: SType },
    /// `GroupGenerator` case object — values.scala:709.
    GroupGenerator { tpe: SType },

    // ── constants (values.scala: Constant[V]; productPrefix = "ConstantNode") ──
    // productIterator: [value, tpe]. N2: tpe field == node.tpe → ALWAYS stripped.
    /// All `Constant[V]` instances; Scala runtime productPrefix = "ConstantNode".
    /// (values.scala:421 `override def productPrefix = "ConstantNode"`)
    Constant { value: ConstPayload, tpe: SType },

    // ── frontend nodes ────────────────────────────────────────────────────────
    /// `Block(bindings: Seq[Val], result: SValue)` — values.scala:1079.
    /// productIterator: [bindings (Seq), result (Value)].
    Block {
        bindings: Vec<TypedExpr>, // must be ValNode variants
        result: Box<TypedExpr>,
        tpe: SType,
    },

    /// `ValNode(name: String, givenType: SType, body: SValue)` — values.scala:1146.
    /// productIterator: [name, givenType, body].
    /// N2: givenType (bare SType) == ValNode.tpe (= givenType) → always stripped.
    ValNode {
        name: String,
        given_type: SType,
        body: Box<TypedExpr>,
        tpe: SType,
    },

    /// `Ident(name: String, tpe: SType)` — values.scala:1192.
    /// productIterator: [name, tpe].
    /// N2: tpe field == node.tpe → always stripped.
    Ident { name: String, tpe: SType },

    /// `Lambda(tpeParams, args, givenResType, body)` — values.scala:1395.
    /// productIterator: [tpeParams (Seq), args (Seq[(String,SType)]),
    ///                   givenResType (SType), body (Option[Value])].
    /// N2: givenResType is a bare SType; Lambda.tpe = SFunc(…) → givenResType ≠ SFunc
    ///     → never stripped in practice.
    Lambda {
        tpe_params: Vec<STypeParam>,
        args: Vec<(String, SType)>,
        given_res_type: SType,
        body: Option<Box<TypedExpr>>,
        tpe: SType,
    },

    /// `Select(obj, field, resType: Option[SType])` — values.scala:1165.
    /// productIterator: [obj (Value), field (String), resType (Option[SType])].
    /// N2 (E6): unwrap Option[SType] → if == node.tpe → skip; else `#Type`; None → "None".
    Select {
        obj: Box<TypedExpr>,
        field: String,
        res_type: Option<SType>,
        tpe: SType,
    },

    /// `Apply(func, args)` — values.scala:1213.
    /// productIterator: [func (Value), args (Seq[Value])].
    Apply {
        func: Box<TypedExpr>,
        args: Vec<TypedExpr>,
        tpe: SType,
    },

    /// `Tuple(items)` — values.scala:778.
    /// productIterator: [items (Seq[Value])].
    Tuple { items: Vec<TypedExpr>, tpe: SType },

    /// `ConcreteCollection(items, elementType: V)` — values.scala:827.
    /// productIterator: [items (Seq), elementType (bare SType)].
    /// N2: elementType (e.g. SInt) ≠ node.tpe (SColl[SInt]) → never stripped.
    ConcreteCollection {
        items: Vec<TypedExpr>,
        elem_type: SType,
        tpe: SType,
    },

    /// `If(condition, trueBranch, falseBranch)` — trees.scala:1302.
    /// productIterator: [condition, trueBranch, falseBranch].
    If {
        condition: Box<TypedExpr>,
        true_branch: Box<TypedExpr>,
        false_branch: Box<TypedExpr>,
        tpe: SType,
    },

    // ── arithmetic / bitwise ops (trees.scala) ───────────────────────────────
    /// `ArithOp(left, right, opCode: Byte)` — trees.scala:704.
    /// productIterator: [left (Value), right (Value), opCode (Byte → i8)].
    /// Opcodes (as signed i8): Plus=-102, Minus=-103, Multiply=-100,
    ///   Division=-99, Modulo=-98, Min=-95, Max=-94.
    /// Source: OpCodes.scala newOpCode(shift) = (LastConstantCode(112) + shift).toByte.
    ArithOp {
        left: Box<TypedExpr>,
        right: Box<TypedExpr>,
        opcode: i8,
        tpe: SType,
    },

    /// `BitOp(left, right, opCode: Byte)` — trees.scala:911.
    /// productIterator: [left, right, opCode].
    /// Opcodes (as signed i8): BitOr=-14, BitAnd=-13, BitXor=-11,
    ///   BitShiftRight=-10, BitShiftLeft=-9, BitShiftRightZeroed=-8.
    /// Source: OpCodes.scala newOpCode(130..136).
    BitOp {
        left: Box<TypedExpr>,
        right: Box<TypedExpr>,
        opcode: i8,
        tpe: SType,
    },

    /// `Upcast(input, tpe: R)` — trees.scala:396.
    /// productIterator: [input (Value), tpe (SType)].
    /// N2: tpe field == node.tpe → always stripped.
    Upcast { input: Box<TypedExpr>, tpe: SType },

    /// `Downcast(input, tpe: R)` — trees.scala:429.
    /// productIterator: [input (Value), tpe (SType)].
    /// N2: tpe field == node.tpe → always stripped.
    Downcast { input: Box<TypedExpr>, tpe: SType },

    // ── relations (trees.scala:1090-1221) ────────────────────────────────────
    // All: productIterator [left, right]. No SType fields → nothing stripped.
    /// `GT(left, right)` — trees.scala (NotReadyValueBoolean result).
    GT {
        left: Box<TypedExpr>,
        right: Box<TypedExpr>,
        tpe: SType,
    },
    /// `GE(left, right)`.
    GE {
        left: Box<TypedExpr>,
        right: Box<TypedExpr>,
        tpe: SType,
    },
    /// `LT(left, right)`.
    LT {
        left: Box<TypedExpr>,
        right: Box<TypedExpr>,
        tpe: SType,
    },
    /// `LE(left, right)`.
    LE {
        left: Box<TypedExpr>,
        right: Box<TypedExpr>,
        tpe: SType,
    },
    /// `EQ(left, right)`.
    EQ {
        left: Box<TypedExpr>,
        right: Box<TypedExpr>,
        tpe: SType,
    },
    /// `NEQ(left, right)`.
    NEQ {
        left: Box<TypedExpr>,
        right: Box<TypedExpr>,
        tpe: SType,
    },

    // ── boolean ops (trees.scala:1242-1378) ──────────────────────────────────
    /// `BinAnd(left, right)` — trees.scala:1265.
    BinAnd {
        left: Box<TypedExpr>,
        right: Box<TypedExpr>,
        tpe: SType,
    },
    /// `BinOr(left, right)` — trees.scala:1242.
    BinOr {
        left: Box<TypedExpr>,
        right: Box<TypedExpr>,
        tpe: SType,
    },
    /// `BinXor(left, right)` — trees.scala:1284.
    BinXor {
        left: Box<TypedExpr>,
        right: Box<TypedExpr>,
        tpe: SType,
    },
    /// `LogicalNot(input)` — trees.scala:1378.
    LogicalNot { input: Box<TypedExpr>, tpe: SType },

    // ── unary numeric ops (trees.scala:881-915) ───────────────────────────────
    /// `Negation(input)` — trees.scala:881.
    Negation { input: Box<TypedExpr>, tpe: SType },
    /// `BitInversion(input)` — trees.scala:899.
    BitInversion { input: Box<TypedExpr>, tpe: SType },

    // ── collection transformers (transformers.scala) ──────────────────────────
    /// `MapCollection(input, mapper)` — transformers.scala:33.
    MapCollection {
        input: Box<TypedExpr>,
        mapper: Box<TypedExpr>,
        tpe: SType,
    },
    /// `Append(input, col2)` — transformers.scala:59.
    Append {
        input: Box<TypedExpr>,
        col2: Box<TypedExpr>,
        tpe: SType,
    },
    /// `Slice(input, from, until)` — transformers.scala:86.
    Slice {
        input: Box<TypedExpr>,
        from: Box<TypedExpr>,
        until: Box<TypedExpr>,
        tpe: SType,
    },
    /// `Filter(input, condition)` — transformers.scala:117.
    Filter {
        input: Box<TypedExpr>,
        condition: Box<TypedExpr>,
        tpe: SType,
    },
    /// `Exists(input, condition)` — transformers.scala:155.
    Exists {
        input: Box<TypedExpr>,
        condition: Box<TypedExpr>,
        tpe: SType,
    },
    /// `ForAll(input, condition)` — transformers.scala:182.
    ForAll {
        input: Box<TypedExpr>,
        condition: Box<TypedExpr>,
        tpe: SType,
    },
    /// `Fold(input, zero, foldOp)` — transformers.scala:217.
    Fold {
        input: Box<TypedExpr>,
        zero: Box<TypedExpr>,
        fold_op: Box<TypedExpr>,
        tpe: SType,
    },
    /// `ByIndex(input, index, default: Option[Value])` — transformers.scala:249.
    /// productIterator: [input, index, default].
    /// default is Option[Value[V]] — rendered as "None" or unwrapped Value.
    ByIndex {
        input: Box<TypedExpr>,
        index: Box<TypedExpr>,
        default: Option<Box<TypedExpr>>,
        tpe: SType,
    },
    /// `SelectField(input, fieldIndex: Byte)` — transformers.scala:291.
    /// productIterator: [input, fieldIndex]. fieldIndex is 1-based.
    SelectField {
        input: Box<TypedExpr>,
        field_index: i8,
        tpe: SType,
    },
    /// `SizeOf(input)` — transformers.scala:357.
    SizeOf { input: Box<TypedExpr>, tpe: SType },

    // ── sigma / boolean coercions ─────────────────────────────────────────────
    /// `BoolToSigmaProp(value)` — trees.scala:32. productIterator: [value].
    BoolToSigmaProp { value: Box<TypedExpr>, tpe: SType },
    /// `SigmaPropIsProven(input)` — transformers.scala:321.
    SigmaPropIsProven { input: Box<TypedExpr>, tpe: SType },
    /// `SigmaPropBytes(input)` — transformers.scala:332.
    SigmaPropBytes { input: Box<TypedExpr>, tpe: SType },

    // ── sigma combiners ───────────────────────────────────────────────────────
    /// `SigmaAnd(items: Seq[SigmaPropValue])` — trees.scala:127.
    SigmaAnd { items: Vec<TypedExpr>, tpe: SType },
    /// `SigmaOr(items: Seq[SigmaPropValue])` — trees.scala:158.
    SigmaOr { items: Vec<TypedExpr>, tpe: SType },

    // ── collection-boolean gates ──────────────────────────────────────────────
    /// `AND(input: Value[SColl[SBoolean]])` — trees.scala:264.
    AND { input: Box<TypedExpr>, tpe: SType },
    /// `OR(input: Value[SColl[SBoolean]])` — trees.scala:195.
    OR { input: Box<TypedExpr>, tpe: SType },
    /// `XorOf(input: Value[SColl[SBoolean]])` — trees.scala:234.
    XorOf { input: Box<TypedExpr>, tpe: SType },

    // ── group-element ops (trees.scala) ──────────────────────────────────────
    /// `MultiplyGroup(left, right)` — trees.scala:1050.
    MultiplyGroup {
        left: Box<TypedExpr>,
        right: Box<TypedExpr>,
        tpe: SType,
    },
    /// `Exponentiate(left, right)` — trees.scala:1028.
    Exponentiate {
        left: Box<TypedExpr>,
        right: Box<TypedExpr>,
        tpe: SType,
    },
    /// `Xor(left, right)` — trees.scala:1001. Byte-array XOR.
    Xor {
        left: Box<TypedExpr>,
        right: Box<TypedExpr>,
        tpe: SType,
    },

    // ── option ops (transformers.scala) ──────────────────────────────────────
    /// `OptionGet(input)` — transformers.scala:598. productIterator: [input].
    OptionGet { input: Box<TypedExpr>, tpe: SType },
    /// `OptionGetOrElse(input, default)` — transformers.scala:622.
    OptionGetOrElse {
        input: Box<TypedExpr>,
        default: Box<TypedExpr>,
        tpe: SType,
    },
    /// `OptionIsDefined(input)` — transformers.scala:653.
    OptionIsDefined { input: Box<TypedExpr>, tpe: SType },

    // ── context access ────────────────────────────────────────────────────────
    /// `GetVar[V](varId: Byte, tpe: SOption[V])` — transformers.scala:576.
    /// productIterator: [varId (Byte), tpe (SOption[V])].
    /// N2: tpe = SOption(V) == GetVar.tpe = SOption(V) → always stripped.
    /// The node's type IS SOption(inner); inner is the variable's value type.
    GetVar { var_id: i8, tpe: SType },

    /// `DeserializeContext[V](id: Byte, tpe: V)` — transformers.scala:552.
    /// productIterator: [id (Byte), tpe (V: SType)].
    /// N2: tpe == node.tpe → always stripped.
    DeserializeContext { id: i8, tpe: SType },

    /// `DeserializeRegister[V](reg: RegisterId, tpe: V, default: Option[V])` — transformers.scala:565.
    /// productIterator: [reg (Byte), tpe (V: SType), default (Option[Value])].
    /// N2: tpe == node.tpe → always stripped.
    DeserializeRegister {
        reg: i8,
        tpe: SType,
        default: Option<Box<TypedExpr>>,
    },

    // ── predef irBuilder outputs ──────────────────────────────────────────────
    /// `CreateProveDlog(value)` — trees.scala:61.
    CreateProveDlog { value: Box<TypedExpr>, tpe: SType },
    /// `CreateProveDHTuple(gv, hv, uv, vv)` — trees.scala:96.
    CreateProveDHTuple {
        gv: Box<TypedExpr>,
        hv: Box<TypedExpr>,
        uv: Box<TypedExpr>,
        vv: Box<TypedExpr>,
        tpe: SType,
    },
    /// `CalcBlake2b256(input)` — trees.scala:545.
    CalcBlake2b256 { input: Box<TypedExpr>, tpe: SType },
    /// `CalcSha256(input)` — trees.scala:591.
    CalcSha256 { input: Box<TypedExpr>, tpe: SType },
    /// `ByteArrayToBigInt(input)` — trees.scala:493.
    ByteArrayToBigInt { input: Box<TypedExpr>, tpe: SType },
    /// `ByteArrayToLong(input)` — trees.scala:473.
    ByteArrayToLong { input: Box<TypedExpr>, tpe: SType },
    /// `LongToByteArray(input)` — trees.scala:453.
    LongToByteArray { input: Box<TypedExpr>, tpe: SType },
    /// `DecodePoint(input)` — trees.scala:513.
    DecodePoint { input: Box<TypedExpr>, tpe: SType },
    /// `SubstConstants(scriptBytes, positions, newValues)` — trees.scala:624.
    SubstConstants {
        script_bytes: Box<TypedExpr>,
        positions: Box<TypedExpr>,
        new_values: Box<TypedExpr>,
        tpe: SType,
    },
    /// `AtLeast(bound, input)` — trees.scala:307.
    AtLeast {
        bound: Box<TypedExpr>,
        input: Box<TypedExpr>,
        tpe: SType,
    },
    /// `CreateAvlTree(operationFlags, digest, keyLength, valueLengthOpt)` — trees.scala:79.
    CreateAvlTree {
        operation_flags: Box<TypedExpr>,
        digest: Box<TypedExpr>,
        key_length: Box<TypedExpr>,
        value_length_opt: Box<TypedExpr>,
        tpe: SType,
    },
    /// `TreeLookup(tree, key, proof)` — trees.scala:1322.
    TreeLookup {
        tree: Box<TypedExpr>,
        key: Box<TypedExpr>,
        proof: Box<TypedExpr>,
        tpe: SType,
    },
    /// `ZKProofBlock(body)` — values.scala:1110.
    ZKProofBlock { body: Box<TypedExpr>, tpe: SType },

    // ── MethodCall (values.scala:1313) ───────────────────────────────────────
    // productIterator: [obj (Value), method (SMethod), args (IndexedSeq), typeSubst (Map)].
    // tpe is derived from method.stype.tRange, NOT a productIterator field.
    // MethodCall and PropertyCall share the same Scala class; productPrefix = "MethodCall".
    /// `MethodCall(obj, method, args, typeSubst)` — values.scala:1313.
    /// Also covers zero-arg `PropertyCall` (same class, productPrefix = "MethodCall").
    /// type_subst: sorted by the printer per N4 (Vec for determinism; printer sorts).
    MethodCall {
        obj: Box<TypedExpr>,
        method: MethodRef,
        args: Vec<TypedExpr>,
        type_subst: Vec<(String, SType)>,
        tpe: SType,
    },
}

/// Return the node's assigned type.
/// Used by the printer for the `:TypeTermString` header and N2 checks.
pub fn node_tpe(e: &TypedExpr) -> &SType {
    match e {
        TypedExpr::Height { tpe }
        | TypedExpr::Self_ { tpe }
        | TypedExpr::Inputs { tpe }
        | TypedExpr::Outputs { tpe }
        | TypedExpr::Context { tpe }
        | TypedExpr::Global { tpe }
        | TypedExpr::MinerPubkey { tpe }
        | TypedExpr::LastBlockUtxoRootHash { tpe }
        | TypedExpr::GroupGenerator { tpe }
        | TypedExpr::Constant { tpe, .. }
        | TypedExpr::Block { tpe, .. }
        | TypedExpr::ValNode { tpe, .. }
        | TypedExpr::Ident { tpe, .. }
        | TypedExpr::Lambda { tpe, .. }
        | TypedExpr::Select { tpe, .. }
        | TypedExpr::Apply { tpe, .. }
        | TypedExpr::Tuple { tpe, .. }
        | TypedExpr::ConcreteCollection { tpe, .. }
        | TypedExpr::If { tpe, .. }
        | TypedExpr::ArithOp { tpe, .. }
        | TypedExpr::BitOp { tpe, .. }
        | TypedExpr::Upcast { tpe, .. }
        | TypedExpr::Downcast { tpe, .. }
        | TypedExpr::GT { tpe, .. }
        | TypedExpr::GE { tpe, .. }
        | TypedExpr::LT { tpe, .. }
        | TypedExpr::LE { tpe, .. }
        | TypedExpr::EQ { tpe, .. }
        | TypedExpr::NEQ { tpe, .. }
        | TypedExpr::BinAnd { tpe, .. }
        | TypedExpr::BinOr { tpe, .. }
        | TypedExpr::BinXor { tpe, .. }
        | TypedExpr::LogicalNot { tpe, .. }
        | TypedExpr::Negation { tpe, .. }
        | TypedExpr::BitInversion { tpe, .. }
        | TypedExpr::MapCollection { tpe, .. }
        | TypedExpr::Append { tpe, .. }
        | TypedExpr::Slice { tpe, .. }
        | TypedExpr::Filter { tpe, .. }
        | TypedExpr::Exists { tpe, .. }
        | TypedExpr::ForAll { tpe, .. }
        | TypedExpr::Fold { tpe, .. }
        | TypedExpr::ByIndex { tpe, .. }
        | TypedExpr::SelectField { tpe, .. }
        | TypedExpr::SizeOf { tpe, .. }
        | TypedExpr::BoolToSigmaProp { tpe, .. }
        | TypedExpr::SigmaPropIsProven { tpe, .. }
        | TypedExpr::SigmaPropBytes { tpe, .. }
        | TypedExpr::SigmaAnd { tpe, .. }
        | TypedExpr::SigmaOr { tpe, .. }
        | TypedExpr::AND { tpe, .. }
        | TypedExpr::OR { tpe, .. }
        | TypedExpr::XorOf { tpe, .. }
        | TypedExpr::MultiplyGroup { tpe, .. }
        | TypedExpr::Exponentiate { tpe, .. }
        | TypedExpr::Xor { tpe, .. }
        | TypedExpr::OptionGet { tpe, .. }
        | TypedExpr::OptionGetOrElse { tpe, .. }
        | TypedExpr::OptionIsDefined { tpe, .. }
        | TypedExpr::GetVar { tpe, .. }
        | TypedExpr::DeserializeContext { tpe, .. }
        | TypedExpr::DeserializeRegister { tpe, .. }
        | TypedExpr::CreateProveDlog { tpe, .. }
        | TypedExpr::CreateProveDHTuple { tpe, .. }
        | TypedExpr::CalcBlake2b256 { tpe, .. }
        | TypedExpr::CalcSha256 { tpe, .. }
        | TypedExpr::ByteArrayToBigInt { tpe, .. }
        | TypedExpr::ByteArrayToLong { tpe, .. }
        | TypedExpr::LongToByteArray { tpe, .. }
        | TypedExpr::DecodePoint { tpe, .. }
        | TypedExpr::SubstConstants { tpe, .. }
        | TypedExpr::AtLeast { tpe, .. }
        | TypedExpr::CreateAvlTree { tpe, .. }
        | TypedExpr::TreeLookup { tpe, .. }
        | TypedExpr::ZKProofBlock { tpe, .. }
        | TypedExpr::MethodCall { tpe, .. } => tpe,
    }
}

/// Return the Scala `productPrefix` for a node — the string used in the s-expression header.
pub fn product_prefix(e: &TypedExpr) -> &'static str {
    match e {
        TypedExpr::Height { .. } => "Height",
        TypedExpr::Self_ { .. } => "Self",
        TypedExpr::Inputs { .. } => "Inputs",
        TypedExpr::Outputs { .. } => "Outputs",
        TypedExpr::Context { .. } => "Context",
        TypedExpr::Global { .. } => "Global",
        TypedExpr::MinerPubkey { .. } => "MinerPubkey",
        TypedExpr::LastBlockUtxoRootHash { .. } => "LastBlockUtxoRootHash",
        TypedExpr::GroupGenerator { .. } => "GroupGenerator",
        // All Constant[V] have productPrefix = "ConstantNode" (values.scala:421).
        TypedExpr::Constant { .. } => "ConstantNode",
        TypedExpr::Block { .. } => "Block",
        TypedExpr::ValNode { .. } => "ValNode",
        TypedExpr::Ident { .. } => "Ident",
        TypedExpr::Lambda { .. } => "Lambda",
        TypedExpr::Select { .. } => "Select",
        TypedExpr::Apply { .. } => "Apply",
        TypedExpr::Tuple { .. } => "Tuple",
        TypedExpr::ConcreteCollection { .. } => "ConcreteCollection",
        TypedExpr::If { .. } => "If",
        TypedExpr::ArithOp { .. } => "ArithOp",
        TypedExpr::BitOp { .. } => "BitOp",
        TypedExpr::Upcast { .. } => "Upcast",
        TypedExpr::Downcast { .. } => "Downcast",
        TypedExpr::GT { .. } => "GT",
        TypedExpr::GE { .. } => "GE",
        TypedExpr::LT { .. } => "LT",
        TypedExpr::LE { .. } => "LE",
        TypedExpr::EQ { .. } => "EQ",
        TypedExpr::NEQ { .. } => "NEQ",
        TypedExpr::BinAnd { .. } => "BinAnd",
        TypedExpr::BinOr { .. } => "BinOr",
        TypedExpr::BinXor { .. } => "BinXor",
        TypedExpr::LogicalNot { .. } => "LogicalNot",
        TypedExpr::Negation { .. } => "Negation",
        TypedExpr::BitInversion { .. } => "BitInversion",
        TypedExpr::MapCollection { .. } => "MapCollection",
        TypedExpr::Append { .. } => "Append",
        TypedExpr::Slice { .. } => "Slice",
        TypedExpr::Filter { .. } => "Filter",
        TypedExpr::Exists { .. } => "Exists",
        TypedExpr::ForAll { .. } => "ForAll",
        TypedExpr::Fold { .. } => "Fold",
        TypedExpr::ByIndex { .. } => "ByIndex",
        TypedExpr::SelectField { .. } => "SelectField",
        TypedExpr::SizeOf { .. } => "SizeOf",
        TypedExpr::BoolToSigmaProp { .. } => "BoolToSigmaProp",
        TypedExpr::SigmaPropIsProven { .. } => "SigmaPropIsProven",
        TypedExpr::SigmaPropBytes { .. } => "SigmaPropBytes",
        TypedExpr::SigmaAnd { .. } => "SigmaAnd",
        TypedExpr::SigmaOr { .. } => "SigmaOr",
        TypedExpr::AND { .. } => "AND",
        TypedExpr::OR { .. } => "OR",
        TypedExpr::XorOf { .. } => "XorOf",
        TypedExpr::MultiplyGroup { .. } => "MultiplyGroup",
        TypedExpr::Exponentiate { .. } => "Exponentiate",
        TypedExpr::Xor { .. } => "Xor",
        TypedExpr::OptionGet { .. } => "OptionGet",
        TypedExpr::OptionGetOrElse { .. } => "OptionGetOrElse",
        TypedExpr::OptionIsDefined { .. } => "OptionIsDefined",
        TypedExpr::GetVar { .. } => "GetVar",
        TypedExpr::DeserializeContext { .. } => "DeserializeContext",
        TypedExpr::DeserializeRegister { .. } => "DeserializeRegister",
        TypedExpr::CreateProveDlog { .. } => "CreateProveDlog",
        TypedExpr::CreateProveDHTuple { .. } => "CreateProveDHTuple",
        TypedExpr::CalcBlake2b256 { .. } => "CalcBlake2b256",
        TypedExpr::CalcSha256 { .. } => "CalcSha256",
        TypedExpr::ByteArrayToBigInt { .. } => "ByteArrayToBigInt",
        TypedExpr::ByteArrayToLong { .. } => "ByteArrayToLong",
        TypedExpr::LongToByteArray { .. } => "LongToByteArray",
        TypedExpr::DecodePoint { .. } => "DecodePoint",
        TypedExpr::SubstConstants { .. } => "SubstConstants",
        TypedExpr::AtLeast { .. } => "AtLeast",
        TypedExpr::CreateAvlTree { .. } => "CreateAvlTree",
        TypedExpr::TreeLookup { .. } => "TreeLookup",
        TypedExpr::ZKProofBlock { .. } => "ZKProofBlock",
        // MethodCall and PropertyCall share the same Scala class (values.scala:1329-1330).
        TypedExpr::MethodCall { .. } => "MethodCall",
    }
}

// ----- ArithOp opcode constants (signed i8) ──────────────────────────────────
// Source: OpCodes.scala newOpCode(shift) = (LastConstantCode(112) + shift).toByte
// LastConstantCode = TypeCodes.LastDataType(111) + 1 = 112.

/// ArithOp Plus opcode: newOpCode(42) = (112+42)=154 as u8 → -102 as i8.
pub const ARITH_PLUS: i8 = -102i8;
/// ArithOp Minus: newOpCode(41) = 153 → -103.
pub const ARITH_MINUS: i8 = -103i8;
/// ArithOp Multiply: newOpCode(44) = 156 → -100.
pub const ARITH_MULTIPLY: i8 = -100i8;
/// ArithOp Division: newOpCode(45) = 157 → -99.
pub const ARITH_DIVISION: i8 = -99i8;
/// ArithOp Modulo: newOpCode(46) = 158 → -98.
pub const ARITH_MODULO: i8 = -98i8;
/// ArithOp Min: newOpCode(49) = 161 → -95.
pub const ARITH_MIN: i8 = -95i8;
/// ArithOp Max: newOpCode(50) = 162 → -94.
pub const ARITH_MAX: i8 = -94i8;

// ----- BitOp opcode constants (signed i8) ────────────────────────────────────

/// BitOp BitOr: newOpCode(130) = 242 → -14.
pub const BIT_OR: i8 = -14i8;
/// BitOp BitAnd: newOpCode(131) = 243 → -13.
pub const BIT_AND: i8 = -13i8;
/// BitOp BitXor: newOpCode(133) = 245 → -11.
pub const BIT_XOR: i8 = -11i8;
/// BitOp BitShiftRight: newOpCode(134) = 246 → -10.
pub const BIT_SHIFT_RIGHT: i8 = -10i8;
/// BitOp BitShiftLeft: newOpCode(135) = 247 → -9.
pub const BIT_SHIFT_LEFT: i8 = -9i8;
/// BitOp BitShiftRightZeroed: newOpCode(136) = 248 → -8.
pub const BIT_SHIFT_RIGHT_ZEROED: i8 = -8i8;

#[cfg(test)]
mod tests {
    use super::*;

    // ----- helpers -----

    fn int_const(v: i32) -> TypedExpr {
        TypedExpr::Constant {
            value: ConstPayload::Int(v),
            tpe: SType::SInt,
        }
    }

    fn long_const(v: i64) -> TypedExpr {
        TypedExpr::Constant {
            value: ConstPayload::Long(v),
            tpe: SType::SLong,
        }
    }

    // ----- happy path -----

    #[test]
    fn context_singletons_have_correct_prefixes() {
        // Verify product_prefix returns the correct Scala class name for each singleton.
        assert_eq!(
            product_prefix(&TypedExpr::Height { tpe: SType::SInt }),
            "Height"
        );
        assert_eq!(
            product_prefix(&TypedExpr::Self_ { tpe: SType::SBox }),
            "Self"
        );
        assert_eq!(
            product_prefix(&TypedExpr::Inputs {
                tpe: SType::SColl(Box::new(SType::SBox))
            }),
            "Inputs"
        );
        assert_eq!(
            product_prefix(&TypedExpr::Global {
                tpe: SType::SGlobal
            }),
            "Global"
        );
        assert_eq!(
            product_prefix(&TypedExpr::Context {
                tpe: SType::SContext
            }),
            "Context"
        );
        assert_eq!(
            product_prefix(&TypedExpr::LastBlockUtxoRootHash {
                tpe: SType::SAvlTree
            }),
            "LastBlockUtxoRootHash"
        );
    }

    #[test]
    fn constant_has_prefix_constantnode() {
        // values.scala:421: `override def productPrefix = "ConstantNode"`
        let c = int_const(42);
        assert_eq!(product_prefix(&c), "ConstantNode");
    }

    #[test]
    fn method_call_has_prefix_methodcall() {
        // values.scala:1329: PropertyCall and MethodCall share the same class.
        let mc = TypedExpr::MethodCall {
            obj: Box::new(TypedExpr::Global {
                tpe: SType::SGlobal,
            }),
            method: MethodRef {
                owner: "SigmaDslBuilder".into(),
                name: "serialize".into(),
            },
            args: vec![int_const(1)],
            type_subst: vec![],
            tpe: SType::SColl(Box::new(SType::SByte)),
        };
        assert_eq!(product_prefix(&mc), "MethodCall");
    }

    #[test]
    fn node_tpe_returns_correct_type() {
        assert_eq!(
            node_tpe(&TypedExpr::Height { tpe: SType::SInt }),
            &SType::SInt
        );
        assert_eq!(node_tpe(&int_const(1)), &SType::SInt);
        assert_eq!(node_tpe(&long_const(1)), &SType::SLong);
        assert_eq!(
            node_tpe(&TypedExpr::ArithOp {
                left: Box::new(long_const(1)),
                right: Box::new(long_const(2)),
                opcode: ARITH_PLUS,
                tpe: SType::SLong,
            }),
            &SType::SLong
        );
    }

    // ----- opcode constants -----

    #[test]
    fn arith_plus_opcode_is_neg102() {
        // OpCodes.scala PlusCode = newOpCode(42) = (112+42)=154 → -102 as i8.
        // Verified by golden seed line 23: `1L + 1` → `... @-102`.
        assert_eq!(ARITH_PLUS, -102i8);
        assert_eq!(ARITH_MINUS, -103i8);
        assert_eq!(ARITH_MULTIPLY, -100i8);
        assert_eq!(ARITH_DIVISION, -99i8);
        assert_eq!(ARITH_MODULO, -98i8);
        assert_eq!(ARITH_MIN, -95i8);
        assert_eq!(ARITH_MAX, -94i8);
    }

    #[test]
    fn bit_opcodes_signed_values() {
        // OpCodes.scala: BitOrCode=newOpCode(130)=242→-14, BitAndCode=131→-13, etc.
        assert_eq!(BIT_OR, -14i8);
        assert_eq!(BIT_AND, -13i8);
        assert_eq!(BIT_XOR, -11i8);
        assert_eq!(BIT_SHIFT_RIGHT, -10i8);
        assert_eq!(BIT_SHIFT_LEFT, -9i8);
        assert_eq!(BIT_SHIFT_RIGHT_ZEROED, -8i8);
    }

    // ----- round-trips -----

    #[test]
    fn typed_expr_clone_and_eq() {
        let e = TypedExpr::ArithOp {
            left: Box::new(long_const(1)),
            right: Box::new(TypedExpr::Upcast {
                input: Box::new(int_const(1)),
                tpe: SType::SLong,
            }),
            opcode: ARITH_PLUS,
            tpe: SType::SLong,
        };
        assert_eq!(e.clone(), e);
    }

    // ----- error paths -----

    #[test]
    fn method_ref_fields_stored_correctly() {
        let mr = MethodRef {
            owner: "SCollection".to_string(),
            name: "zip".to_string(),
        };
        assert_eq!(mr.owner, "SCollection");
        assert_eq!(mr.name, "zip");
    }

    #[test]
    fn const_payload_variants_exist() {
        // Smoke-test that all payload variants construct without panic.
        let _ = ConstPayload::Bool(true);
        let _ = ConstPayload::Byte(1);
        let _ = ConstPayload::Short(100);
        let _ = ConstPayload::Int(42);
        let _ = ConstPayload::Long(1_000_000);
        let _ = ConstPayload::BigInt("5".into());
        let _ = ConstPayload::Unit;
        let _ = ConstPayload::ByteColl(vec![1, 2]);
        let _ = ConstPayload::LongColl(vec![1, 2]);
        let _ = ConstPayload::GroupElement("(x,y,1)".into());
        let _ = ConstPayload::SigmaProp("...".into());
    }
}
