//! Untyped AST produced by the parser. One variant per node the Scala parser
//! can emit (sigma.ast values.scala, frontend nodes with opCode=Undefined plus
//! the surviving constant/op nodes). Distinct from the ergo-ser opcode IR by
//! design (design doc §6): this is a semantic tree with names and spans.

use crate::span::Pos;
use crate::stype::SType;

/// `val name (: T)? = body` binding (values.scala:1146 ValNode).
#[derive(Debug, Clone, PartialEq)]
pub struct ValDef {
    pub name: String,
    pub given_type: SType, // NoType when unascribed (SigmaParser.scala:26-30)
    pub body: Expr,
    pub pos: Pos,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArithKind {
    Minus,
    Divide,
    Modulo,
} // trees.scala:704 ArithOp opcodes

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BitKind {
    Or,
    And,
} // trees.scala:911 BitOp

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelKind {
    Eq,
    Neq,
    Ge,
    Gt,
    Le,
    Lt,
} // trees.scala:1090-1221

#[derive(Debug, Clone, PartialEq)]
pub enum Expr {
    // ----- constants (values already validated by the lexer/parser) -----
    IntConst {
        value: i32,
        pos: Pos,
    }, // Literals.scala:106-116, default Int
    LongConst {
        value: i64,
        pos: Pos,
    }, // suffix L/l
    BoolConst {
        value: bool,
        pos: Pos,
    }, // Literals.scala:72-77
    /// Raw captured string with only delimiting `"` stripped — escapes are NOT
    /// decoded (Literals.scala:119-124). Also carries the `null`, `'c'`, `'sym`
    /// and id-prefixed-string quirk forms (recon-lexical.md §4-5).
    StringConst {
        value: String,
        pos: Pos,
    },
    UnitConst {
        pos: Pos,
    }, // SigmaBuilder.scala:652

    // ----- frontend nodes (eliminated by binder/typer in M2+) -----
    Ident {
        name: String,
        tpe: SType,
        pos: Pos,
    }, // values.scala:1192; tpe=NoType
    // except the ZKProof callee
    Select {
        obj: Box<Expr>,
        field: String,
        pos: Pos,
    }, // values.scala:1165
    Apply {
        func: Box<Expr>,
        args: Vec<Expr>,
        pos: Pos,
    }, // values.scala:1213
    ApplyTypes {
        input: Box<Expr>,
        type_args: Vec<SType>,
        pos: Pos,
    }, // values.scala:1257
    MethodCallLike {
        obj: Box<Expr>,
        name: String,
        args: Vec<Expr>,
        pos: Pos,
    }, // values.scala:1282
    Lambda {
        args: Vec<(String, SType)>, // NoType when unascribed
        given_res_type: SType,      // NoType except `def f(...): R`
        body: Box<Expr>,
        pos: Pos,
    }, // values.scala:1395; tpeParams always empty
    Val(Box<ValDef>), // a `val`/`def` in statement position
    Block {
        bindings: Vec<ValDef>,
        result: Box<Expr>,
        pos: Pos,
    }, // values.scala:1079
    Tuple {
        items: Vec<Expr>,
        pos: Pos,
    }, // values.scala:778
    If {
        condition: Box<Expr>,
        true_branch: Box<Expr>,
        false_branch: Box<Expr>,
        pos: Pos,
    },

    // ----- operation nodes built by mk_unary_op / mk_binary_op -----
    LogicalNot {
        input: Box<Expr>,
        pos: Pos,
    }, // trees.scala:1378
    Negation {
        input: Box<Expr>,
        pos: Pos,
    }, // trees.scala:881
    BitInversion {
        input: Box<Expr>,
        pos: Pos,
    }, // trees.scala:899
    Relation {
        kind: RelKind,
        left: Box<Expr>,
        right: Box<Expr>,
        pos: Pos,
    },
    ArithOp {
        kind: ArithKind,
        left: Box<Expr>,
        right: Box<Expr>,
        pos: Pos,
    },
    BitOp {
        kind: BitKind,
        left: Box<Expr>,
        right: Box<Expr>,
        pos: Pos,
    },
}

/// `SNumericType` membership (SType.scala:412-547): Byte, Short, Int, Long,
/// BigInt, UnsignedBigInt. Mirrors `isNumType` (package.scala:133).
fn is_numeric(t: &SType) -> bool {
    matches!(
        t,
        SType::SByte
            | SType::SShort
            | SType::SInt
            | SType::SLong
            | SType::SBigInt
            | SType::SUnsignedBigInt
    )
}

/// Scala's `SType.?:` (values.scala:1152/1406): `given` unless it is `NoType`,
/// otherwise the lazily-computed fallback.
fn or_no_type(given: &SType, fallback: impl FnOnce() -> SType) -> SType {
    if *given == SType::NoType {
        fallback()
    } else {
        given.clone()
    }
}

/// Scala `Select.tpe`'s product branch (values.scala:1171-1178):
/// `obj.tpe match { case p: SProduct => MethodsContainer.getMethod(p, field)
/// .map(_.stype).getOrElse(NoType); case _ => NoType }`. Every `SMethod.stype` is
/// an `SFunc` (methods.scala:216-228 `propertyCall`, and every `SMethod`
/// constructor), so a FOUND method yields an `SFunc` (never numeric, never
/// `NoType` — it fails the mkUnaryOp/mkBinaryOp numeric guard); a MISSING method,
/// or a non-`SProduct` receiver, yields `NoType` (which passes the guard). The
/// returned `SFunc`'s RANGE is the method's real result type read raw from
/// `m.stype` (Scala does NOT substitute the receiver's element type — the range
/// keeps the generic `STypeVar`s of the descriptor). It is consumed by
/// `Apply.parse_tpe` (values.scala:1218-1222), e.g. `-(5.toBytes(0))` REJECTs
/// because `Apply(Select(5,toBytes),[0]).tpe = SColl[SByte]`, and
/// `-(5.toBytes().apply(0))` REJECTs because `Coll.apply`'s range is the generic
/// `tIV = STypeVar("IV")` (methods.scala:940-941), non-numeric. The DOM is never
/// inspected by any `parse_tpe` consumer, so the receiver stands in for it.
///
/// This is the COMPLETE closure of `SProduct` method tables reachable from the
/// parse-time-typed roots `parse_tpe` can produce. The reachable-receiver set is
/// finite and closed under method-range types (every range is a numeric, `SColl`,
/// `SOption`, `STuple`, `SBoolean`, or an `STypeVar` — the last is not `SProduct`,
/// SType.scala:287, so it terminates at `NoType`):
/// - `STuple` (tuple literal / paren≥2) — [`tuple_method_range`]
///   (methods.scala:1248-1257).
/// - numerics `SByte`/`SShort`/`SInt`/`SLong` (casts / arith / `x.toByte()` …) —
///   [`numeric_shared_range`] (`SNumericTypeMethods`, methods.scala:288-478).
/// - `SBigInt` (`x.toBigInt()`) — shared numeric table plus the v6-only
///   `SBigIntMethods` extras (`toUnsigned`/`toUnsignedMod`, methods.scala:546-565).
/// - `SUnsignedBigInt` (`x.toBigInt().toUnsigned()` at v6) — shared numeric table
///   plus the `SUnsignedBigIntMethods` extras (methods.scala:576-623); the type
///   has NO method container at v5 (methodsV6-only, methods.scala:169) → all
///   fields `NoType` there.
/// - `SColl[_]` (`x.toBytes()`/`x.toBits()`, or a `SColl`-returning method) —
///   [`collection_method_range`] (`SCollectionMethods`, methods.scala:821-1216).
/// - `SOption[_]` (`coll.get(i)` at v6, methods.scala:1183-1189) —
///   [`option_method_range`] (`SOptionMethods`, methods.scala:750-799).
/// - `SBoolean`/`SString` are `SProduct` but define NO methods
///   (`SBooleanMethods`/`SStringMethods` `getMethods = super = Nil`, methods.scala:
///   511/628) → `NoType`, same as the `_` arm below.
/// - `SUnit`/`SAny`/`SFunc`/`STypeVar` are NOT `SProduct` (SType.scala:626/639/660/
///   287) → the `_ => NoType` arm. `SGroupElement`/`SBox`/`SAvlTree`/… are `SProduct`
///   but NOT parse-time reachable (only ever `NoType` `Ident`s), so no table is ported.
fn product_method_tpe(obj_tpe: &SType, field: &str, tree_version: u8) -> SType {
    match method_range(obj_tpe, field, tree_version) {
        Some(res) => SType::SFunc {
            dom: vec![obj_tpe.clone()],
            range: Box::new(res),
        },
        None => SType::NoType,
    }
}

/// The result type (`SFunc` range) of `MethodsContainer.getMethod(receiver, field)`
/// at `tree_version`, or `None` when the method is absent (a missing method, an
/// empty-table `SProduct`, or a non-`SProduct` receiver — all `NoType`).
fn method_range(receiver: &SType, field: &str, tree_version: u8) -> Option<SType> {
    match receiver {
        SType::STuple(items) => tuple_method_range(items, field),
        SType::SColl(_) => collection_method_range(field, tree_version),
        SType::SOption(_) => option_method_range(field),
        SType::SByte | SType::SShort | SType::SInt | SType::SLong => {
            numeric_shared_range(field, receiver, tree_version)
        }
        // SBigInt: shared numeric methods + v6-only SBigIntMethods extras.
        SType::SBigInt => numeric_shared_range(field, receiver, tree_version)
            .or_else(|| bigint_extra_range(field, tree_version)),
        // SUnsignedBigInt only has a method container at v6 (methodsV6-only,
        // methods.scala:169); at v5 the container lookup misses → NoType.
        SType::SUnsignedBigInt if tree_version >= 3 => {
            numeric_shared_range(field, receiver, tree_version)
                .or_else(|| unsigned_bigint_extra_range(field))
        }
        _ => None,
    }
}

/// `STupleMethods.getTupleMethod` result type (methods.scala:1248-1257) for a tuple
/// receiver, or `None` when `field` is not a tuple method.
fn tuple_method_range(items: &[SType], field: &str) -> Option<SType> {
    // colMethods inherited from Coll (methods.scala:1240-1246): `size` (id 1) →
    // `SInt`, `apply` (id 10) → `SAny` (elemType after the `tIV -> SAny` subst
    // that is applied ONLY for tuples, methods.scala:1241).
    match field {
        "size" => return Some(SType::SInt),
        "apply" => return Some(SType::SAny),
        _ => {}
    }
    // `_i` component: `SFunc(tup, tup.items(i-1))`, valid iff
    // `componentNames.lastIndexOf("_i", end = len-1) != -1`, i.e. `1 <= i <= len`
    // (methods.scala:1250). `componentNames` holds exactly "_1".."_MaxTupleLength",
    // so a non-canonical form ("_0", "_01", "_-1") never matches.
    let rest = field.strip_prefix('_')?;
    let i: usize = rest.parse().ok()?;
    if i >= 1 && i <= items.len() && rest == i.to_string() {
        Some(items[i - 1].clone())
    } else {
        None
    }
}

/// `SNumericTypeMethods` result type (methods.scala:288-478) shared by every numeric
/// receiver `recv`; the `tNum` type variable is substituted by `recv`
/// (methods.scala:235). `None` when `field` is not a shared numeric method at
/// `tree_version`.
fn numeric_shared_range(field: &str, recv: &SType, tree_version: u8) -> Option<SType> {
    // v5 set (methods.scala:288-336, 461-469): present at every version.
    match field {
        "toByte" => return Some(SType::SByte),
        "toShort" => return Some(SType::SShort),
        "toInt" => return Some(SType::SInt),
        "toLong" => return Some(SType::SLong),
        "toBigInt" => return Some(SType::SBigInt),
        "toBytes" => return Some(SType::SColl(Box::new(SType::SByte))),
        "toBits" => return Some(SType::SColl(Box::new(SType::SBoolean))),
        _ => {}
    }
    // v6-only additions (`isV3OrLaterErgoTreeVersion` == `tree_version >= 3`;
    // methods.scala:355-459, 471-478): each returns the receiver numeric type.
    if tree_version >= 3
        && matches!(
            field,
            "bitwiseInverse"
                | "bitwiseOr"
                | "bitwiseAnd"
                | "bitwiseXor"
                | "shiftLeft"
                | "shiftRight"
        )
    {
        Some(recv.clone())
    } else {
        None
    }
}

/// v6-only `SBigIntMethods` extras (methods.scala:546-565), added on top of the
/// shared numeric table for a `SBigInt` receiver at `tree_version >= 3`.
fn bigint_extra_range(field: &str, tree_version: u8) -> Option<SType> {
    if tree_version < 3 {
        return None;
    }
    match field {
        // toUnsigned: SFunc(SBigInt, SUnsignedBigInt) (methods.scala:546).
        "toUnsigned" => Some(SType::SUnsignedBigInt),
        // toUnsignedMod: SFunc([SBigInt, SUnsignedBigInt], SUnsignedBigInt) (:553).
        "toUnsignedMod" => Some(SType::SUnsignedBigInt),
        _ => None,
    }
}

/// `SUnsignedBigIntMethods` extras (methods.scala:576-623), added on top of the
/// shared numeric table for a `SUnsignedBigInt` receiver. The container exists only
/// at v6 (gated by the caller in [`method_range`]); the extras themselves carry no
/// further version gate (methods.scala:613-623).
fn unsigned_bigint_extra_range(field: &str) -> Option<SType> {
    match field {
        // All five modular ops return the receiver `SUnsignedBigInt`
        // (methods.scala:576-605).
        "modInverse" | "plusMod" | "subtractMod" | "multiplyMod" | "mod" => {
            Some(SType::SUnsignedBigInt)
        }
        // toSigned: SFunc([SUnsignedBigInt], SBigInt) (methods.scala:609).
        "toSigned" => Some(SType::SBigInt),
        _ => None,
    }
}

/// `SCollectionMethods` result type (methods.scala:821-1216) for a `SColl[_]`
/// receiver. Ranges are read RAW from the descriptor — the generic element vars
/// `tIV = STypeVar("IV")` / `tOV = STypeVar("OV")` (SType.scala:88-89) are NOT
/// substituted with the receiver's element type (Scala uses `m.stype`
/// unchanged, values.scala:1174). `None` when `field` is not a Coll method at
/// `tree_version`. The lookup is element-agnostic (keyed by the `SCollection`
/// type code), matching `MethodsContainer.getMethod`.
fn collection_method_range(field: &str, tree_version: u8) -> Option<SType> {
    let tiv = || SType::STypeVar("IV".to_string());
    let tov = || SType::STypeVar("OV".to_string());
    let coll = |t: SType| SType::SColl(Box::new(t));
    // v5 set (methods.scala:1191-1209): present at every version.
    let v5 = match field {
        "size" => Some(SType::SInt),                            // :821
        "getOrElse" => Some(tiv()),                             // :824
        "map" => Some(coll(tov())),                             // :846 tOVColl
        "exists" => Some(SType::SBoolean),                      // :869
        "fold" => Some(tov()),                                  // :880
        "forall" => Some(SType::SBoolean),                      // :891
        "slice" => Some(coll(tiv())),                           // :903 ThisType
        "filter" => Some(coll(tiv())),                          // :919 ThisType
        "append" => Some(coll(tiv())),                          // :931 ThisType
        "apply" => Some(tiv()),                                 // :940
        "indices" => Some(coll(SType::SInt)),                   // :954
        "flatMap" => Some(coll(tov())),                         // :982 tOVColl
        "patch" => Some(coll(tiv())),                           // :1013 ThisType
        "updated" => Some(coll(tiv())),                         // :1033 ThisType
        "updateMany" => Some(coll(tiv())),                      // :1053 ThisType
        "indexOf" => Some(SType::SInt),                         // :1070
        "zip" => Some(coll(SType::STuple(vec![tiv(), tov()]))), // :1105
        _ => None,
    };
    if v5.is_some() {
        return v5;
    }
    // v6-only additions (methods.scala:1211-1216; `isV3OrLaterErgoTreeVersion`).
    if tree_version >= 3 {
        match field {
            "reverse" => Some(coll(tiv())),                 // :1126 ThisType
            "startsWith" => Some(SType::SBoolean),          // :1145
            "endsWith" => Some(SType::SBoolean),            // :1165
            "get" => Some(SType::SOption(Box::new(tiv()))), // :1183
            _ => None,
        }
    } else {
        None
    }
}

/// `SOptionMethods` result type (methods.scala:750-799) for a `SOption[_]` receiver.
/// The table is version-independent (`getMethods` has no gate, methods.scala:792);
/// `SOption` is only parse-time-reachable at v6 via `Coll.get`, but the lookup
/// itself is unconditional, mirroring the reference. Ranges keep the generic vars
/// `tT = STypeVar("T")` / `tR = STypeVar("R")` (SType.scala:81-82), unsubstituted.
fn option_method_range(field: &str) -> Option<SType> {
    match field {
        "isDefined" => Some(SType::SBoolean),                  // :750
        "get" => Some(SType::STypeVar("T".to_string())),       // :758 tT
        "getOrElse" => Some(SType::STypeVar("T".to_string())), // :765 tT
        "map" => Some(SType::SOption(Box::new(SType::STypeVar("R".to_string())))), // :775 SOption(tR)
        "filter" => Some(SType::SOption(Box::new(SType::STypeVar("T".to_string())))), // :784 ThisType
        _ => None,
    }
}

impl Expr {
    /// The node's source position (every node has one —
    /// SigmaParserTest `assertSrcCtxForAllNodes`, LangTests.scala).
    pub fn pos(&self) -> Pos {
        match self {
            Expr::IntConst { pos, .. } => *pos,
            Expr::LongConst { pos, .. } => *pos,
            Expr::BoolConst { pos, .. } => *pos,
            Expr::StringConst { pos, .. } => *pos,
            Expr::UnitConst { pos } => *pos,
            Expr::Ident { pos, .. } => *pos,
            Expr::Select { pos, .. } => *pos,
            Expr::Apply { pos, .. } => *pos,
            Expr::ApplyTypes { pos, .. } => *pos,
            Expr::MethodCallLike { pos, .. } => *pos,
            Expr::Lambda { pos, .. } => *pos,
            Expr::Val(val_def) => val_def.pos,
            Expr::Block { pos, .. } => *pos,
            Expr::Tuple { pos, .. } => *pos,
            Expr::If { pos, .. } => *pos,
            Expr::LogicalNot { pos, .. } => *pos,
            Expr::Negation { pos, .. } => *pos,
            Expr::BitInversion { pos, .. } => *pos,
            Expr::Relation { pos, .. } => *pos,
            Expr::ArithOp { pos, .. } => *pos,
            Expr::BitOp { pos, .. } => *pos,
        }
    }

    /// The parse-time node type, mirroring the Scala frontend AST `tpe`
    /// definitions EXACTLY (paths under `sigmastate-interpreter/.../sigma/ast/`).
    /// The `mkUnaryOp`/`mkBinaryOp` numeric guards (SigmaParser.scala:44/55/61/
    /// 85/91) read `arg.tpe`, and the reference nodes carry a DERIVED type — not
    /// a blanket `NoType` — so an approximation that treats every non-constant as
    /// `NoType` wrongly accepts e.g. `-(1 == 2)` (a Relation is `SBoolean`, not
    /// `NoType`). Each arm cites the mirrored Scala `tpe`:
    ///
    /// - `IntConst`/`LongConst`/`BoolConst`/`StringConst`/`UnitConst` — the
    ///   constant's own type (Literals.scala:72-124, SigmaBuilder.scala:652).
    /// - `Ident` — its `tpe` field (values.scala:1192; `NoType` except the
    ///   ZKProof callee, which carries `SFunc`).
    /// - `Select` — `resType.getOrElse(obj.tpe match { SProduct => method-lookup;
    ///   _ => NoType })` (values.scala:1171-1178), delegated to
    ///   [`product_method_tpe`], which ports the COMPLETE closure of reachable
    ///   method tables (tuple / numeric / `SColl` / `SOption` / v6 BigInt).
    ///   `resType` is `None` at parse time; a NoType/identifier-rooted object stays
    ///   `NoType` (so `-OUTPUTS.size` accepts), but a parse-time-typed *product*
    ///   object — a tuple literal `(a,b)._i`, a numeric constant `.toByte`, a
    ///   `SColl` `5.toBytes().size`, an `SOption` `…get(0).isDefined`, a v6
    ///   `5.toBigInt().toUnsigned` — resolves through the reference method tables,
    ///   and a FOUND method makes the Select an `SFunc` (non-numeric). This is why
    ///   `-((1,2)._1)` / `((1,true)._2) | 1` / `-(5.toByte)` /
    ///   `-(5.toBytes().size)` / `-(5.toBigInt().toUnsigned)` REJECT
    ///   (oracle-verified) while we used to accept.
    /// - `Apply` — `func.tpe match { SFunc => range; SColl => elem; _ => NoType }`
    ///   (values.scala:1218-1222).
    /// - `ApplyTypes` — `input.tpe` (values.scala:1262-1267; `applySubst` on an
    ///   `SFunc` stays an `SFunc`, so the numeric/NoType classification of
    ///   `input` is preserved).
    /// - `MethodCallLike` — `NoType` default (values.scala:1282).
    /// - `Lambda` — `SFunc(args, givenResType ?: body.tpe)` (values.scala:1404-1407).
    /// - `Val`/`ValNode` — `givenType ?: body.tpe` (values.scala:1152).
    /// - `Block` — `result.tpe` (values.scala:1082).
    /// - `Tuple` — `STuple(items.map(_.tpe))` (values.scala:783).
    /// - `If` — `trueBranch.tpe` (trees.scala:1348-1351).
    /// - `LogicalNot` — `SBoolean` (trees.scala:1378).
    /// - `Negation`/`BitInversion` — `input.tpe` (trees.scala:881-884/899-902).
    /// - `Relation` — `SBoolean` (trees.scala:1072-1073, `NotReadyValueBoolean`).
    /// - `ArithOp` — `left.tpe` (trees.scala:704-707).
    /// - `BitOp` — `left.tpe` (trees.scala:911-915).
    pub fn parse_tpe(&self, tree_version: u8) -> SType {
        match self {
            Expr::IntConst { .. } => SType::SInt,
            Expr::LongConst { .. } => SType::SLong,
            Expr::BoolConst { .. } => SType::SBoolean,
            Expr::StringConst { .. } => SType::SString,
            Expr::UnitConst { .. } => SType::SUnit,
            Expr::Ident { tpe, .. } => tpe.clone(),
            Expr::Select { obj, field, .. } => {
                product_method_tpe(&obj.parse_tpe(tree_version), field, tree_version)
            }
            Expr::Apply { func, .. } => match func.parse_tpe(tree_version) {
                SType::SFunc { range, .. } => *range,
                SType::SColl(elem) => *elem,
                _ => SType::NoType,
            },
            Expr::ApplyTypes { input, .. } => input.parse_tpe(tree_version),
            Expr::MethodCallLike { .. } => SType::NoType,
            Expr::Lambda {
                args,
                given_res_type,
                body,
                ..
            } => SType::SFunc {
                dom: args.iter().map(|(_, t)| t.clone()).collect(),
                range: Box::new(or_no_type(given_res_type, || body.parse_tpe(tree_version))),
            },
            Expr::Val(val_def) => {
                or_no_type(&val_def.given_type, || val_def.body.parse_tpe(tree_version))
            }
            Expr::Block { result, .. } => result.parse_tpe(tree_version),
            Expr::Tuple { items, .. } => {
                SType::STuple(items.iter().map(|e| e.parse_tpe(tree_version)).collect())
            }
            Expr::If { true_branch, .. } => true_branch.parse_tpe(tree_version),
            Expr::LogicalNot { .. } => SType::SBoolean,
            Expr::Negation { input, .. } => input.parse_tpe(tree_version),
            Expr::BitInversion { input, .. } => input.parse_tpe(tree_version),
            Expr::Relation { .. } => SType::SBoolean,
            Expr::ArithOp { left, .. } => left.parse_tpe(tree_version),
            Expr::BitOp { left, .. } => left.parse_tpe(tree_version),
        }
    }

    /// The `isNumTypeOrNoType` guard (package.scala:139): the node's parse-time
    /// type is numeric (`SNumericType`: Byte/Short/Int/Long/BigInt/UnsignedBigInt,
    /// SType.scala:412-547) or `NoType`. Used by `mk_unary_op`/`mk_binary_op` for
    /// `-`/`~`/`|`/`&`.
    pub fn is_num_type_or_no_type(&self, tree_version: u8) -> bool {
        let t = self.parse_tpe(tree_version);
        is_numeric(&t) || t == SType::NoType
    }

    /// True only for IntConst/LongConst — the mkUnaryOp "-" constant-fold guard
    /// (`isInstanceOf[Constant] && tpe.isNumType`, SigmaParser.scala:43).
    pub fn is_numeric_constant(&self) -> bool {
        matches!(self, Expr::IntConst { .. } | Expr::LongConst { .. })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- helpers -----
    fn make_pos(offset: u32) -> Pos {
        offset
    }

    // ----- happy path -----
    #[test]
    fn int_const_construction_and_pos() {
        let expr = Expr::IntConst {
            value: 42,
            pos: make_pos(10),
        };
        assert_eq!(expr.pos(), 10);
    }

    #[test]
    fn long_const_construction_and_pos() {
        let expr = Expr::LongConst {
            value: 9223372036854775807i64,
            pos: make_pos(20),
        };
        assert_eq!(expr.pos(), 20);
    }

    #[test]
    fn bool_const_construction_and_pos() {
        let expr = Expr::BoolConst {
            value: true,
            pos: make_pos(5),
        };
        assert_eq!(expr.pos(), 5);
    }

    #[test]
    fn string_const_construction_and_pos() {
        let expr = Expr::StringConst {
            value: "hello".to_string(),
            pos: make_pos(15),
        };
        assert_eq!(expr.pos(), 15);
    }

    #[test]
    fn unit_const_construction_and_pos() {
        let expr = Expr::UnitConst { pos: make_pos(8) };
        assert_eq!(expr.pos(), 8);
    }

    #[test]
    fn ident_construction_and_pos() {
        let expr = Expr::Ident {
            name: "x".to_string(),
            tpe: SType::NoType,
            pos: make_pos(25),
        };
        assert_eq!(expr.pos(), 25);
    }

    #[test]
    fn lambda_construction_and_pos() {
        let expr = Expr::Lambda {
            args: vec![("x".to_string(), SType::SInt)],
            given_res_type: SType::NoType,
            body: Box::new(Expr::Ident {
                name: "x".to_string(),
                tpe: SType::NoType,
                pos: make_pos(30),
            }),
            pos: make_pos(28),
        };
        assert_eq!(expr.pos(), 28);
    }

    #[test]
    fn block_construction_and_pos() {
        let val_def = ValDef {
            name: "x".to_string(),
            given_type: SType::SInt,
            body: Expr::IntConst {
                value: 5,
                pos: make_pos(35),
            },
            pos: make_pos(32),
        };
        let expr = Expr::Block {
            bindings: vec![val_def],
            result: Box::new(Expr::Ident {
                name: "x".to_string(),
                tpe: SType::NoType,
                pos: make_pos(40),
            }),
            pos: make_pos(31),
        };
        assert_eq!(expr.pos(), 31);
    }

    #[test]
    fn val_expr_construction_and_pos() {
        let val_def = ValDef {
            name: "y".to_string(),
            given_type: SType::SLong,
            body: Expr::LongConst {
                value: 100i64,
                pos: make_pos(50),
            },
            pos: make_pos(45),
        };
        let expr = Expr::Val(Box::new(val_def));
        assert_eq!(expr.pos(), 45);
    }

    #[test]
    fn if_expr_construction_and_pos() {
        let expr = Expr::If {
            condition: Box::new(Expr::BoolConst {
                value: true,
                pos: make_pos(60),
            }),
            true_branch: Box::new(Expr::IntConst {
                value: 1,
                pos: make_pos(65),
            }),
            false_branch: Box::new(Expr::IntConst {
                value: 0,
                pos: make_pos(70),
            }),
            pos: make_pos(55),
        };
        assert_eq!(expr.pos(), 55);
    }

    #[test]
    fn select_construction_and_pos() {
        let expr = Expr::Select {
            obj: Box::new(Expr::Ident {
                name: "obj".to_string(),
                tpe: SType::NoType,
                pos: make_pos(75),
            }),
            field: "field".to_string(),
            pos: make_pos(72),
        };
        assert_eq!(expr.pos(), 72);
    }

    #[test]
    fn apply_construction_and_pos() {
        let expr = Expr::Apply {
            func: Box::new(Expr::Ident {
                name: "f".to_string(),
                tpe: SType::NoType,
                pos: make_pos(82),
            }),
            args: vec![Expr::IntConst {
                value: 1,
                pos: make_pos(85),
            }],
            pos: make_pos(80),
        };
        assert_eq!(expr.pos(), 80);
    }

    #[test]
    fn is_num_type_or_no_type_int_const() {
        let expr = Expr::IntConst {
            value: 42,
            pos: make_pos(0),
        };
        assert!(expr.is_num_type_or_no_type(3));
    }

    #[test]
    fn is_num_type_or_no_type_long_const() {
        let expr = Expr::LongConst {
            value: 42i64,
            pos: make_pos(0),
        };
        assert!(expr.is_num_type_or_no_type(3));
    }

    #[test]
    fn is_num_type_or_no_type_bool_const_false() {
        let expr = Expr::BoolConst {
            value: false,
            pos: make_pos(0),
        };
        assert!(!expr.is_num_type_or_no_type(3));
    }

    #[test]
    fn is_num_type_or_no_type_string_const_false() {
        let expr = Expr::StringConst {
            value: "test".to_string(),
            pos: make_pos(0),
        };
        assert!(!expr.is_num_type_or_no_type(3));
    }

    #[test]
    fn is_num_type_or_no_type_unit_const_false() {
        let expr = Expr::UnitConst { pos: make_pos(0) };
        assert!(!expr.is_num_type_or_no_type(3));
    }

    #[test]
    fn is_num_type_or_no_type_ident_true() {
        let expr = Expr::Ident {
            name: "x".to_string(),
            tpe: SType::NoType,
            pos: make_pos(0),
        };
        assert!(expr.is_num_type_or_no_type(3));
    }

    #[test]
    fn is_num_type_or_no_type_apply_true() {
        let expr = Expr::Apply {
            func: Box::new(Expr::Ident {
                name: "f".to_string(),
                tpe: SType::NoType,
                pos: make_pos(1),
            }),
            args: vec![],
            pos: make_pos(0),
        };
        assert!(expr.is_num_type_or_no_type(3));
    }

    // ----- parse-time type derivation (parse_tpe) -----

    #[test]
    fn parse_tpe_constants_are_their_own_type() {
        assert_eq!(
            Expr::IntConst { value: 1, pos: 0 }.parse_tpe(3),
            SType::SInt
        );
        assert_eq!(
            Expr::LongConst { value: 1, pos: 0 }.parse_tpe(3),
            SType::SLong
        );
        assert_eq!(
            Expr::BoolConst {
                value: true,
                pos: 0
            }
            .parse_tpe(3),
            SType::SBoolean
        );
        assert_eq!(
            Expr::StringConst {
                value: "s".into(),
                pos: 0
            }
            .parse_tpe(3),
            SType::SString
        );
        assert_eq!(Expr::UnitConst { pos: 0 }.parse_tpe(3), SType::SUnit);
    }

    #[test]
    fn parse_tpe_relation_and_logical_not_are_sboolean() {
        // trees.scala:1072-1073 (NotReadyValueBoolean), :1378.
        let rel = Expr::Relation {
            kind: RelKind::Eq,
            left: Box::new(Expr::IntConst { value: 1, pos: 0 }),
            right: Box::new(Expr::IntConst { value: 2, pos: 0 }),
            pos: 0,
        };
        assert_eq!(rel.parse_tpe(3), SType::SBoolean);
        assert!(!rel.is_num_type_or_no_type(3)); // SBoolean fails the numeric guard
        let not = Expr::LogicalNot {
            input: Box::new(Expr::Ident {
                name: "x".into(),
                tpe: SType::NoType,
                pos: 0,
            }),
            pos: 0,
        };
        assert_eq!(not.parse_tpe(3), SType::SBoolean);
        assert!(!not.is_num_type_or_no_type(3));
    }

    #[test]
    fn parse_tpe_tuple_is_stuple_of_item_tpes() {
        // values.scala:783.
        let t = Expr::Tuple {
            items: vec![
                Expr::IntConst { value: 1, pos: 0 },
                Expr::BoolConst {
                    value: true,
                    pos: 0,
                },
            ],
            pos: 0,
        };
        assert_eq!(
            t.parse_tpe(3),
            SType::STuple(vec![SType::SInt, SType::SBoolean])
        );
        assert!(!t.is_num_type_or_no_type(3)); // STuple fails the numeric guard
    }

    #[test]
    fn parse_tpe_block_is_result_tpe() {
        // values.scala:1082 — a Block of a NoType result passes the guard, a Block
        // of a numeric/bool result takes that result's type.
        let numeric_result = Expr::Block {
            bindings: vec![],
            result: Box::new(Expr::Ident {
                name: "x".into(),
                tpe: SType::NoType,
                pos: 0,
            }),
            pos: 0,
        };
        assert_eq!(numeric_result.parse_tpe(3), SType::NoType);
        assert!(numeric_result.is_num_type_or_no_type(3));
        let bool_result = Expr::Block {
            bindings: vec![],
            result: Box::new(Expr::BoolConst {
                value: true,
                pos: 0,
            }),
            pos: 0,
        };
        assert_eq!(bool_result.parse_tpe(3), SType::SBoolean);
        assert!(!bool_result.is_num_type_or_no_type(3));
    }

    #[test]
    fn parse_tpe_arith_and_if_recurse_into_children() {
        // trees.scala:704-707 (ArithOp -> left.tpe), :1348-1351 (If -> trueBranch.tpe).
        let arith = Expr::ArithOp {
            kind: ArithKind::Minus,
            left: Box::new(Expr::IntConst { value: 1, pos: 0 }),
            right: Box::new(Expr::IntConst { value: 2, pos: 0 }),
            pos: 0,
        };
        assert_eq!(arith.parse_tpe(3), SType::SInt);
        assert!(arith.is_num_type_or_no_type(3));
        let if_bool = Expr::If {
            condition: Box::new(Expr::Ident {
                name: "c".into(),
                tpe: SType::NoType,
                pos: 0,
            }),
            true_branch: Box::new(Expr::BoolConst {
                value: true,
                pos: 0,
            }),
            false_branch: Box::new(Expr::BoolConst {
                value: false,
                pos: 0,
            }),
            pos: 0,
        };
        assert_eq!(if_bool.parse_tpe(3), SType::SBoolean);
        assert!(!if_bool.is_num_type_or_no_type(3));
    }

    #[test]
    fn parse_tpe_apply_derives_from_func_range() {
        // values.scala:1218-1222 — Apply of an SFunc callee (the ZKProof Ident)
        // yields the SFunc's range (SBoolean here); an Apply of a NoType callee is
        // NoType.
        let zk = Expr::Apply {
            func: Box::new(Expr::Ident {
                name: "ZKProof".into(),
                tpe: SType::SFunc {
                    dom: vec![SType::SSigmaProp],
                    range: Box::new(SType::SBoolean),
                },
                pos: 0,
            }),
            args: vec![Expr::Ident {
                name: "p".into(),
                tpe: SType::NoType,
                pos: 0,
            }],
            pos: 0,
        };
        assert_eq!(zk.parse_tpe(3), SType::SBoolean);
        let plain = Expr::Apply {
            func: Box::new(Expr::Ident {
                name: "f".into(),
                tpe: SType::NoType,
                pos: 0,
            }),
            args: vec![],
            pos: 0,
        };
        assert_eq!(plain.parse_tpe(3), SType::NoType);
    }

    #[test]
    fn parse_tpe_lambda_is_sfunc() {
        // values.scala:1404-1407.
        let lam = Expr::Lambda {
            args: vec![("x".into(), SType::SInt)],
            given_res_type: SType::NoType,
            body: Box::new(Expr::Ident {
                name: "x".into(),
                tpe: SType::NoType,
                pos: 0,
            }),
            pos: 0,
        };
        assert!(matches!(lam.parse_tpe(3), SType::SFunc { .. }));
        assert!(!lam.is_num_type_or_no_type(3));
    }

    // ----- Select product-method lookup (values.scala:1171-1178) -----

    fn select(obj: Expr, field: &str) -> Expr {
        Expr::Select {
            obj: Box::new(obj),
            field: field.into(),
            pos: 0,
        }
    }

    fn tuple2(a: Expr, b: Expr) -> Expr {
        Expr::Tuple {
            items: vec![a, b],
            pos: 0,
        }
    }

    fn int(v: i32) -> Expr {
        Expr::IntConst { value: v, pos: 0 }
    }

    #[test]
    fn parse_tpe_select_tuple_component_in_range_is_sfunc() {
        // `(1,2)._1`: STuple is SProduct, `_1` resolves (1<=1<=2) to
        // SFunc(tup, items(0)) → non-numeric → the numeric guard FAILS.
        // oracle: `-((1,2)._1)` REJECT.
        let s = select(tuple2(int(1), int(2)), "_1");
        assert!(matches!(s.parse_tpe(3), SType::SFunc { .. }));
        assert!(!s.is_num_type_or_no_type(3));
    }

    #[test]
    fn parse_tpe_select_tuple_component_out_of_range_is_no_type() {
        // `(1,2)._3`: `_3` is out of range on a 2-tuple → None → NoType → guard
        // passes. oracle: `-((1,2)._3)` ACCEPT.
        let s = select(tuple2(int(1), int(2)), "_3");
        assert_eq!(s.parse_tpe(3), SType::NoType);
        assert!(s.is_num_type_or_no_type(3));
    }

    #[test]
    fn parse_tpe_select_tuple_non_canonical_component_is_no_type() {
        // `_0` / `_01` are not in `componentNames` → NoType. oracle:
        // `-((1,2)._0)` / `-((1,2)._01)` ACCEPT.
        for field in ["_0", "_01"] {
            let s = select(tuple2(int(1), int(2)), field);
            assert_eq!(s.parse_tpe(3), SType::NoType, "{field}");
        }
    }

    #[test]
    fn parse_tpe_select_tuple_coll_method_is_sfunc() {
        // `(1,2).size` / `(1,2).apply` inherit Coll methods → SFunc. oracle:
        // `-((1,2).size)` / `~((1,2).apply)` REJECT.
        for field in ["size", "apply"] {
            let s = select(tuple2(int(1), int(2)), field);
            assert!(matches!(s.parse_tpe(3), SType::SFunc { .. }), "{field}");
        }
    }

    #[test]
    fn parse_tpe_select_numeric_cast_method_is_sfunc_with_result_range() {
        // `5.toBytes`: SInt has `toBytes` → SFunc(SInt, SColl[SByte]); the Select
        // itself is SFunc (guard fails), and an Apply of it takes the range.
        // oracle: `-(5.toBytes(0))` REJECT (range SColl non-numeric),
        // `-(5.toByte(0))` ACCEPT (range SByte numeric).
        let s = select(int(5), "toBytes");
        match s.parse_tpe(3) {
            SType::SFunc { range, .. } => assert_eq!(*range, SType::SColl(Box::new(SType::SByte))),
            other => panic!("expected SFunc, got {other:?}"),
        }
        assert!(!s.is_num_type_or_no_type(3));
        let apply = Expr::Apply {
            func: Box::new(select(int(5), "toByte")),
            args: vec![int(0)],
            pos: 0,
        };
        assert_eq!(apply.parse_tpe(3), SType::SByte); // numeric → guard passes
        assert!(apply.is_num_type_or_no_type(3));
    }

    #[test]
    fn parse_tpe_select_numeric_bitwise_method_is_version_gated() {
        // `bitwiseOr` is a v6-only numeric method (tree_version>=3). oracle:
        // `-(5.bitwiseOr)` REJECT at v6.
        let s = select(int(5), "bitwiseOr");
        assert!(matches!(s.parse_tpe(3), SType::SFunc { .. }));
        assert!(!s.is_num_type_or_no_type(3));
        // At v5 the method does not exist → NoType → guard passes.
        assert_eq!(s.parse_tpe(0), SType::NoType);
        assert!(s.is_num_type_or_no_type(0));
    }

    #[test]
    fn parse_tpe_select_no_type_or_empty_product_object_is_no_type() {
        // A NoType identifier object (`OUTPUTS.size`), and SBoolean/SString/SUnit
        // receivers (no methods / not SProduct), all stay NoType → guard passes.
        // oracle: `-OUTPUTS.size`, `-(true.toByte)`, `-("ab".size)`, `-(().foo)`
        // all ACCEPT.
        let ident_obj = select(
            Expr::Ident {
                name: "OUTPUTS".into(),
                tpe: SType::NoType,
                pos: 0,
            },
            "size",
        );
        assert_eq!(ident_obj.parse_tpe(3), SType::NoType);
        let bool_obj = select(
            Expr::BoolConst {
                value: true,
                pos: 0,
            },
            "toByte",
        );
        assert_eq!(bool_obj.parse_tpe(3), SType::NoType);
        let str_obj = select(
            Expr::StringConst {
                value: "ab".into(),
                pos: 0,
            },
            "size",
        );
        assert_eq!(str_obj.parse_tpe(3), SType::NoType);
        let unit_obj = select(Expr::UnitConst { pos: 0 }, "foo");
        assert_eq!(unit_obj.parse_tpe(3), SType::NoType);
    }

    // ----- method-table closure (SColl / SOption / v6 BigInt) -----

    /// `Apply(f, args)` — parses `f`'s callee-tpe per values.scala:1218-1222.
    fn call(f: Expr, args: Vec<Expr>) -> Expr {
        Expr::Apply {
            func: Box::new(f),
            args,
            pos: 0,
        }
    }

    /// `5.toBytes()` — an `SColl[SByte]`-typed receiver (Apply of the numeric
    /// `toBytes` cast, whose SFunc range is read by Apply).
    fn coll_recv() -> Expr {
        call(select(int(5), "toBytes"), vec![])
    }

    /// `5.toBigInt()` — an `SBigInt`-typed receiver.
    fn bigint_recv() -> Expr {
        call(select(int(5), "toBigInt"), vec![])
    }

    /// `5.toBigInt().toUnsigned()` — an `SUnsignedBigInt`-typed receiver (v6).
    fn ubigint_recv() -> Expr {
        call(select(bigint_recv(), "toUnsigned"), vec![])
    }

    #[test]
    fn parse_tpe_coll_receiver_has_scollection_type() {
        // Sanity: `5.toBytes()` derives to SColl[SByte] (numeric toBytes range).
        assert_eq!(
            coll_recv().parse_tpe(3),
            SType::SColl(Box::new(SType::SByte))
        );
    }

    #[test]
    fn parse_tpe_select_coll_method_is_sfunc() {
        // SColl is SProduct with SCollectionMethods → found method → SFunc →
        // non-numeric → guard FAILS. oracle: `-(5.toBytes().size)`,
        // `5.toBytes().apply | 1`, `-(5.toBytes().indexOf)`, `-(5.toBytes().map)`
        // all REJECT.
        for field in ["size", "apply", "indexOf", "map", "slice", "getOrElse"] {
            let s = select(coll_recv(), field);
            assert!(matches!(s.parse_tpe(3), SType::SFunc { .. }), "{field}");
            assert!(!s.is_num_type_or_no_type(3), "{field}");
        }
    }

    #[test]
    fn parse_tpe_select_coll_v6_method_is_version_gated() {
        // reverse/startsWith/endsWith/get are v6-only (tree_version>=3). oracle:
        // `-(5.toBytes().reverse)` / `-(5.toBytes().get)` REJECT at v6.
        for field in ["reverse", "startsWith", "endsWith", "get"] {
            let s = select(coll_recv(), field);
            assert!(matches!(s.parse_tpe(3), SType::SFunc { .. }), "{field} v6");
            // At v5 the method does not exist → NoType → guard passes.
            assert_eq!(s.parse_tpe(0), SType::NoType, "{field} v5");
        }
    }

    #[test]
    fn parse_tpe_select_coll_unknown_field_is_no_type() {
        // A missing Coll method → getMethod None → NoType → guard passes. oracle:
        // `-(5.toBytes().nosuchmethod)` ACCEPT.
        let s = select(coll_recv(), "nosuchmethod");
        assert_eq!(s.parse_tpe(3), SType::NoType);
        assert!(s.is_num_type_or_no_type(3));
    }

    #[test]
    fn parse_tpe_coll_method_ranges_drive_apply_verdict() {
        // The SFunc range read by Apply (values.scala:1218-1222):
        //  size    → SInt      numeric  → guard passes. oracle:
        //                      `-(5.toBytes().size(0))` ACCEPT.
        let size_call = call(select(coll_recv(), "size"), vec![int(0)]);
        assert_eq!(size_call.parse_tpe(3), SType::SInt);
        assert!(size_call.is_num_type_or_no_type(3));
        //  exists  → SBoolean  non-numeric → guard fails. oracle:
        //                      `-(5.toBytes().exists(0))` REJECT.
        let exists_call = call(select(coll_recv(), "exists"), vec![int(0)]);
        assert_eq!(exists_call.parse_tpe(3), SType::SBoolean);
        assert!(!exists_call.is_num_type_or_no_type(3));
        //  apply   → generic tIV (NOT the SByte element) → non-numeric → fails.
        //                      oracle: `-(5.toBytes().apply(0))` REJECT.
        let apply_call = call(select(coll_recv(), "apply"), vec![int(0)]);
        assert_eq!(apply_call.parse_tpe(3), SType::STypeVar("IV".to_string()));
        assert!(!apply_call.is_num_type_or_no_type(3));
    }

    #[test]
    fn parse_tpe_coll_index_apply_stays_scalar() {
        // Regression: `5.toBytes()(0)` is Apply-ON-SColl (not `.apply`), so it
        // reads the ELEMENT type SByte (numeric) → guard passes. oracle:
        // `-(5.toBytes()(0))` ACCEPT.
        let indexed = call(coll_recv(), vec![int(0)]);
        assert_eq!(indexed.parse_tpe(3), SType::SByte);
        assert!(indexed.is_num_type_or_no_type(3));
    }

    #[test]
    fn parse_tpe_select_option_method_is_sfunc() {
        // `5.toBytes().get(0)` is SOption[tIV] (v6 Coll.get range). SOption is
        // SProduct with SOptionMethods → found method → SFunc. oracle:
        // `-(5.toBytes().get(0).isDefined)` / `.getOrElse` REJECT.
        let opt = call(select(coll_recv(), "get"), vec![int(0)]);
        assert_eq!(
            opt.parse_tpe(3),
            SType::SOption(Box::new(SType::STypeVar("IV".to_string())))
        );
        for field in ["isDefined", "get", "getOrElse", "map", "filter"] {
            let s = select(opt.clone(), field);
            assert!(matches!(s.parse_tpe(3), SType::SFunc { .. }), "{field}");
        }
        // Unknown SOption field → NoType. oracle:
        // `-(5.toBytes().get(0).nosuch)` ACCEPT.
        let unknown = select(opt, "nosuch");
        assert_eq!(unknown.parse_tpe(3), SType::NoType);
    }

    #[test]
    fn parse_tpe_select_bigint_v6_extra_is_version_gated() {
        // SBigInt v6 extras toUnsigned/toUnsignedMod (SBigIntMethods). oracle:
        // `-(5.toBigInt().toUnsigned)` / `-(5.toBigInt().toUnsignedMod)` REJECT.
        for field in ["toUnsigned", "toUnsignedMod"] {
            let s = select(bigint_recv(), field);
            assert!(matches!(s.parse_tpe(3), SType::SFunc { .. }), "{field} v6");
            // Absent at v5 → NoType (source-derived; oracle runs v6 only).
            assert_eq!(s.parse_tpe(0), SType::NoType, "{field} v5");
        }
        // Shared numeric methods also resolve on SBigInt. oracle:
        // `5.toBigInt().toBytes | 1` REJECT.
        let s = select(bigint_recv(), "toBytes");
        assert!(matches!(s.parse_tpe(3), SType::SFunc { .. }));
        // toUnsigned's range is SUnsignedBigInt (numeric) → an Apply of it passes.
        // oracle: `-(5.toBigInt().toUnsigned())` ACCEPT.
        assert_eq!(ubigint_recv().parse_tpe(3), SType::SUnsignedBigInt);
    }

    #[test]
    fn parse_tpe_select_unsigned_bigint_method_is_sfunc() {
        // SUnsignedBigInt (reachable via toUnsigned()) → SUnsignedBigIntMethods.
        // oracle: `-(5.toBigInt().toUnsigned().modInverse)` /
        // `-(5.toBigInt().toUnsigned().toSigned)` / `.toBytes` REJECT.
        for field in [
            "modInverse",
            "plusMod",
            "subtractMod",
            "multiplyMod",
            "mod",
            "toSigned",
            "toBytes",
        ] {
            let s = select(ubigint_recv(), field);
            assert!(matches!(s.parse_tpe(3), SType::SFunc { .. }), "{field}");
        }
        // toSigned's range is SBigInt (numeric) → Apply passes. oracle:
        // `-(5.toBigInt().toUnsigned().toSigned())` ACCEPT.
        let to_signed = call(select(ubigint_recv(), "toSigned"), vec![]);
        assert_eq!(to_signed.parse_tpe(3), SType::SBigInt);
        assert!(to_signed.is_num_type_or_no_type(3));
        // Unknown field → NoType.
        let unknown = select(ubigint_recv(), "nosuch");
        assert_eq!(unknown.parse_tpe(3), SType::NoType);
    }

    #[test]
    fn parse_tpe_unsigned_bigint_receiver_has_no_methods_at_v5() {
        // Source-derived: SUnsignedBigInt has NO method container at v5
        // (methodsV6-only) → any field is NoType. (Not parse-reachable at v5,
        // but the table must mirror the container gate.)
        let recv = SType::SUnsignedBigInt;
        assert_eq!(product_method_tpe(&recv, "modInverse", 0), SType::NoType);
        assert_eq!(product_method_tpe(&recv, "toBytes", 0), SType::NoType);
    }

    #[test]
    fn is_numeric_constant_int_const() {
        let expr = Expr::IntConst {
            value: 42,
            pos: make_pos(0),
        };
        assert!(expr.is_numeric_constant());
    }

    #[test]
    fn is_numeric_constant_long_const() {
        let expr = Expr::LongConst {
            value: 100i64,
            pos: make_pos(0),
        };
        assert!(expr.is_numeric_constant());
    }

    #[test]
    fn is_numeric_constant_bool_const_false() {
        let expr = Expr::BoolConst {
            value: true,
            pos: make_pos(0),
        };
        assert!(!expr.is_numeric_constant());
    }

    #[test]
    fn is_numeric_constant_string_const_false() {
        let expr = Expr::StringConst {
            value: "test".to_string(),
            pos: make_pos(0),
        };
        assert!(!expr.is_numeric_constant());
    }

    #[test]
    fn is_numeric_constant_unit_const_false() {
        let expr = Expr::UnitConst { pos: make_pos(0) };
        assert!(!expr.is_numeric_constant());
    }

    #[test]
    fn is_numeric_constant_ident_false() {
        let expr = Expr::Ident {
            name: "x".to_string(),
            tpe: SType::NoType,
            pos: make_pos(0),
        };
        assert!(!expr.is_numeric_constant());
    }

    #[test]
    fn is_numeric_constant_apply_false() {
        let expr = Expr::Apply {
            func: Box::new(Expr::Ident {
                name: "f".to_string(),
                tpe: SType::NoType,
                pos: make_pos(1),
            }),
            args: vec![],
            pos: make_pos(0),
        };
        assert!(!expr.is_numeric_constant());
    }

    #[test]
    fn tuple_construction_and_pos() {
        let expr = Expr::Tuple {
            items: vec![
                Expr::IntConst {
                    value: 1,
                    pos: make_pos(92),
                },
                Expr::IntConst {
                    value: 2,
                    pos: make_pos(95),
                },
            ],
            pos: make_pos(90),
        };
        assert_eq!(expr.pos(), 90);
    }

    #[test]
    fn negation_construction_and_pos() {
        let expr = Expr::Negation {
            input: Box::new(Expr::IntConst {
                value: 5,
                pos: make_pos(102),
            }),
            pos: make_pos(100),
        };
        assert_eq!(expr.pos(), 100);
    }

    #[test]
    fn relation_eq_construction_and_pos() {
        let expr = Expr::Relation {
            kind: RelKind::Eq,
            left: Box::new(Expr::IntConst {
                value: 1,
                pos: make_pos(110),
            }),
            right: Box::new(Expr::IntConst {
                value: 1,
                pos: make_pos(115),
            }),
            pos: make_pos(107),
        };
        assert_eq!(expr.pos(), 107);
    }

    #[test]
    fn arith_op_construction_and_pos() {
        let expr = Expr::ArithOp {
            kind: ArithKind::Minus,
            left: Box::new(Expr::IntConst {
                value: 5,
                pos: make_pos(125),
            }),
            right: Box::new(Expr::IntConst {
                value: 3,
                pos: make_pos(130),
            }),
            pos: make_pos(122),
        };
        assert_eq!(expr.pos(), 122);
    }

    #[test]
    fn bit_op_construction_and_pos() {
        let expr = Expr::BitOp {
            kind: BitKind::Or,
            left: Box::new(Expr::IntConst {
                value: 1,
                pos: make_pos(140),
            }),
            right: Box::new(Expr::IntConst {
                value: 2,
                pos: make_pos(145),
            }),
            pos: make_pos(137),
        };
        assert_eq!(expr.pos(), 137);
    }
}
