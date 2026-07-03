//! SMethod tables for the ErgoScript typer.
//!
//! Transcription of `sigma/ast/methods.scala` (sigma-state v6.0.2, pinned
//! reference at `/home/rkadias/coding/reference/ergo-core/
//!   sigmastate-interpreter-v6.0.2/data/shared/src/main/scala/sigma/ast/methods.scala`).
//!
//! Only the type-inference surface is reproduced here: no cost models, no
//! irInfo builders.  The `has_ir_builder` flag records whether the Scala side
//! has a `withIRInfo(...)` call on that method — if `true` the typer emits a
//! `MethodCall` node; if `false` it emits a `Select` node (the lowering phase
//! converts both to their final IR forms).
//!
//! # Container map
//!
//! Non-empty containers (17):
//!   SByte(2) SShort(3) SInt(4) SLong(5) SBigInt(6) SGroupElement(7)
//!   SSigmaProp(8) SUnsignedBigInt(9) SColl(12) SOption(36) STuple(96)
//!   SBox(99) SAvlTree(100) SContext(101) SHeader(104) SPreHeader(105)
//!   SGlobal(106)
//!
//! Empty containers — recognized as product types but have no methods:
//!   SBoolean  SString  SAny  SUnit
//!
//! # has_ir_builder semantics
//!
//! `true`  → the Scala `SMethod` was constructed with `.withIRInfo(...)`,
//!            either `MethodCallIrBuilder` (→ MethodCall in typed tree) or a
//!            custom builder (→ lowered IR node, but NOT a Select).
//! `false` → `irInfo.irBuilder` is `None`; the typer emits a `Select` node.
//!            Confirmed by golden seed:
//!              `1.toByte + 2.toByte` → `Select:Byte` nodes (cast ids 1-5);
//!              `b.value`             → `Select:Long`  (SBox.value id 1).
//!
//! # Version axis (min_version)
//!
//! `0` = V5-era: present at all tree versions.
//! `3` = V6/EIP-50: requires `isV3OrLaterErgoTreeVersion` (ergoTree version ≥ 3).

use std::sync::OnceLock;

use crate::stype::SType;
use crate::typer::unify::{apply_subst_func, unify_type_lists, SFuncSpec};

// ─────────────────────────────────────────────────────────────────────────────
// Public types
// ─────────────────────────────────────────────────────────────────────────────

/// A method descriptor entry for one ErgoScript SMethod.
///
/// `stype.dom[0]` is always the receiver type.
#[derive(Debug, Clone)]
pub struct SMethodDesc {
    /// Scala method name as written in ErgoScript (e.g. `"toByte"`, `"zip"`).
    pub name: &'static str,
    /// On-wire method id byte (within the owning type's namespace).
    pub method_id: u8,
    /// Full function signature including receiver in `dom[0]`.
    pub stype: SFuncSpec,
    /// `true` iff the Scala `SMethod.irInfo.irBuilder` is `Some(...)`.
    ///
    /// This is a 2-way flag: it records *presence* only.  The distinction between
    /// `MethodCallIrBuilder` (→ `MethodCall` in the typed tree) and a custom builder
    /// (→ a specialized IR node, e.g. `Exponentiate`, `MapCollection`) is handled by
    /// the lowering dispatch in Tasks 5–7 — do **not** add a 3-way enum here.
    pub has_ir_builder: bool,
    /// `true` iff the on-wire encoding carries an explicit type argument
    /// (`hasExplicitTypeArgs = Seq(tT)` in Scala; affects wire format).
    pub explicit_type_args: bool,
    /// Minimum ErgoTree version required: `0` = V5-era, `3` = V6 only.
    pub min_version: u8,
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal constructor helpers
// ─────────────────────────────────────────────────────────────────────────────

// Type shorthand helpers (module-level pure functions — no captures, usable
// freely inside OnceLock::get_or_init closures).

#[inline(always)]
fn col_byte() -> SType {
    SType::SColl(Box::new(SType::SByte))
}
#[inline(always)]
fn col_bool() -> SType {
    SType::SColl(Box::new(SType::SBoolean))
}
#[inline(always)]
fn tv(s: &str) -> SType {
    SType::STypeVar(s.into())
}
#[inline(always)]
fn scoll(t: SType) -> SType {
    SType::SColl(Box::new(t))
}
#[inline(always)]
fn sopt(t: SType) -> SType {
    SType::SOption(Box::new(t))
}
#[inline(always)]
fn stup(items: Vec<SType>) -> SType {
    SType::STuple(items)
}

// The macro expands to an SMethodDesc literal.
// Variants encode the four (explicit_type_args, has_ir_builder, min_version)
// combinations that appear in the 6.0.2 method tables:
//   v5   → V5-era, has irBuilder  (MethodCallIrBuilder or custom)
//   v5s  → V5-era, NO irBuilder   (Select path; "s" for "select")
//   v6   → V6-only, has irBuilder
//   v6e  → V6-only, has irBuilder + wire explicit type arg
macro_rules! md {
    // V5-era, has irBuilder
    (v5; $name:literal, $id:literal, $dom:expr, $range:expr, $tp:expr) => {
        SMethodDesc {
            name: $name,
            method_id: $id,
            stype: SFuncSpec {
                dom: $dom,
                range: $range,
                tpe_params: $tp,
            },
            has_ir_builder: true,
            explicit_type_args: false,
            min_version: 0,
        }
    };
    // V5-era, NO irBuilder → Select node
    (v5s; $name:literal, $id:literal, $dom:expr, $range:expr, $tp:expr) => {
        SMethodDesc {
            name: $name,
            method_id: $id,
            stype: SFuncSpec {
                dom: $dom,
                range: $range,
                tpe_params: $tp,
            },
            has_ir_builder: false,
            explicit_type_args: false,
            min_version: 0,
        }
    };
    // V6-only, has irBuilder
    (v6; $name:literal, $id:literal, $dom:expr, $range:expr, $tp:expr) => {
        SMethodDesc {
            name: $name,
            method_id: $id,
            stype: SFuncSpec {
                dom: $dom,
                range: $range,
                tpe_params: $tp,
            },
            has_ir_builder: true,
            explicit_type_args: false,
            min_version: 3,
        }
    };
    // V6-only, has irBuilder, wire explicit type arg
    (v6e; $name:literal, $id:literal, $dom:expr, $range:expr, $tp:expr) => {
        SMethodDesc {
            name: $name,
            method_id: $id,
            stype: SFuncSpec {
                dom: $dom,
                range: $range,
                tpe_params: $tp,
            },
            has_ir_builder: true,
            explicit_type_args: true,
            min_version: 3,
        }
    };
}

// ─────────────────────────────────────────────────────────────────────────────
// SNumericTypeMethods — shared across SByte/SShort/SInt/SLong/SBigInt/
//                       SUnsignedBigInt  (methods.scala:260-502)
//
// All 13 shared methods use the concrete receiver type (TNum pre-substituted).
// Cast methods (ids 1-5) have no withIRInfo → Select node path.
// PropertyCall methods (ids 6-7) have MethodCallIrBuilder → MethodCall.
// Bitwise/shift methods (ids 8-13) are V6, MethodCallIrBuilder.
// ─────────────────────────────────────────────────────────────────────────────

fn numeric_shared(recv: SType) -> Vec<SMethodDesc> {
    let r = recv;
    vec![
        // Cast methods — no withIRInfo → Select path (ids 1-5)
        md!(v5s; "toByte",          1,  vec![r.clone()], SType::SByte,          vec![]),
        md!(v5s; "toShort",         2,  vec![r.clone()], SType::SShort,         vec![]),
        md!(v5s; "toInt",           3,  vec![r.clone()], SType::SInt,           vec![]),
        md!(v5s; "toLong",          4,  vec![r.clone()], SType::SLong,          vec![]),
        md!(v5s; "toBigInt",        5,  vec![r.clone()], SType::SBigInt,        vec![]),
        // PropertyCall with MethodCallIrBuilder (ids 6-7)
        // Confirmed by golden seed: `n1.toBytes → MethodCall:Coll[Byte]`
        md!(v5; "toBytes",          6,  vec![r.clone()], col_byte(),             vec![]),
        md!(v5; "toBits",           7,  vec![r.clone()], col_bool(),             vec![]),
        // V6 bitwise/shift — MethodCallIrBuilder (ids 8-13)
        md!(v6; "bitwiseInverse",   8,  vec![r.clone()],                       r.clone(), vec![]),
        md!(v6; "bitwiseOr",        9,  vec![r.clone(), r.clone()],            r.clone(), vec![]),
        md!(v6; "bitwiseAnd",       10, vec![r.clone(), r.clone()],            r.clone(), vec![]),
        md!(v6; "bitwiseXor",       11, vec![r.clone(), r.clone()],            r.clone(), vec![]),
        md!(v6; "shiftLeft",        12, vec![r.clone(), SType::SInt],          r.clone(), vec![]),
        md!(v6; "shiftRight",       13, vec![r.clone(), SType::SInt],          r.clone(), vec![]),
    ]
}

// ─────────────────────────────────────────────────────────────────────────────
// Per-type container initializers
// ─────────────────────────────────────────────────────────────────────────────

fn byte_methods() -> &'static Vec<SMethodDesc> {
    static METHODS: OnceLock<Vec<SMethodDesc>> = OnceLock::new();
    METHODS.get_or_init(|| numeric_shared(SType::SByte))
}

fn short_methods() -> &'static Vec<SMethodDesc> {
    static METHODS: OnceLock<Vec<SMethodDesc>> = OnceLock::new();
    METHODS.get_or_init(|| numeric_shared(SType::SShort))
}

fn int_methods() -> &'static Vec<SMethodDesc> {
    static METHODS: OnceLock<Vec<SMethodDesc>> = OnceLock::new();
    METHODS.get_or_init(|| numeric_shared(SType::SInt))
}

fn long_methods() -> &'static Vec<SMethodDesc> {
    static METHODS: OnceLock<Vec<SMethodDesc>> = OnceLock::new();
    METHODS.get_or_init(|| numeric_shared(SType::SLong))
}

// SBigInt (type_id = 6): 13 shared + 2 extras (methods.scala:546-565).
// id 14 comment in source says "id=8" — actual code is 14; see m2-tables.md §delta3.
fn bigint_methods() -> &'static Vec<SMethodDesc> {
    static METHODS: OnceLock<Vec<SMethodDesc>> = OnceLock::new();
    METHODS.get_or_init(|| {
        let mut v = numeric_shared(SType::SBigInt);
        let u = SType::SUnsignedBigInt;
        // V6-only extras
        v.push(md!(v6; "toUnsigned",    14, vec![SType::SBigInt],              u.clone(), vec![]));
        v.push(md!(v6; "toUnsignedMod", 15, vec![SType::SBigInt, u.clone()],  u.clone(), vec![]));
        v
    })
}

// SUnsignedBigInt (type_id = 9): V6-only type.
// All methods (1-19) are V6 (min_version=3).
// Shared 1-13 still use min_version=3 since the type itself is V6-only
// and ergo-ser correctly excludes type_id 9 from is_v5_method.
fn unsigned_bigint_methods() -> &'static Vec<SMethodDesc> {
    static METHODS: OnceLock<Vec<SMethodDesc>> = OnceLock::new();
    METHODS.get_or_init(|| {
        // Shared numeric methods but all gated at V6 (type doesn't exist pre-v3).
        let shared_v5 = numeric_shared(SType::SUnsignedBigInt);
        // Re-gate all of them to V6.
        let mut v: Vec<SMethodDesc> = shared_v5
            .into_iter()
            .map(|mut d| {
                d.min_version = 3;
                d
            })
            .collect();
        // V6 extras (ids 14-19) — methods.scala:576-609
        let u = SType::SUnsignedBigInt;
        v.push(md!(v6; "modInverse",    14, vec![u.clone(), u.clone()],             u.clone(), vec![]));
        v.push(md!(v6; "plusMod",       15, vec![u.clone(), u.clone(), u.clone()],  u.clone(), vec![]));
        v.push(md!(v6; "subtractMod",   16, vec![u.clone(), u.clone(), u.clone()],  u.clone(), vec![]));
        v.push(md!(v6; "multiplyMod",   17, vec![u.clone(), u.clone(), u.clone()],  u.clone(), vec![]));
        v.push(md!(v6; "mod",           18, vec![u.clone(), u.clone()],             u.clone(), vec![]));
        v.push(md!(v6; "toSigned",      19, vec![u.clone()],                       SType::SBigInt, vec![]));
        v
    })
}

// SGroupElement (type_id = 7): methods.scala:634-690.
// id 1 is absent.  exp/multiply have custom irBuilders (→ Exponentiate/MultiplyGroup).
// getEncoded/negate are PropertyCall with MethodCallIrBuilder.
// expUnsigned is V6 with MethodCallIrBuilder.
// Confirmed: `g1.negate → MethodCall` (golden seed §4).
fn group_element_methods() -> &'static Vec<SMethodDesc> {
    static METHODS: OnceLock<Vec<SMethodDesc>> = OnceLock::new();
    METHODS.get_or_init(|| {
        let g = SType::SGroupElement;
        vec![
            // id 1 absent
            md!(v5; "getEncoded",   2, vec![g.clone()],                            col_byte(),         vec![]),
            md!(v5; "exp",          3, vec![g.clone(), SType::SBigInt],            g.clone(),          vec![]),
            md!(v5; "multiply",     4, vec![g.clone(), g.clone()],                 g.clone(),          vec![]),
            md!(v5; "negate",       5, vec![g.clone()],                            g.clone(),          vec![]),
            md!(v6; "expUnsigned",  6, vec![g.clone(), SType::SUnsignedBigInt],   g.clone(),          vec![]),
        ]
    })
}

// SSigmaProp (type_id = 8): methods.scala:694-714.
// Both have NO withIRInfo → Select nodes.
// propBytes: lowered via Select → SigmaPropBytes opcode 0xD0.
// isProven: frontend-only (costKind=null).
fn sigma_prop_methods() -> &'static Vec<SMethodDesc> {
    static METHODS: OnceLock<Vec<SMethodDesc>> = OnceLock::new();
    METHODS.get_or_init(|| {
        let s = SType::SSigmaProp;
        vec![
            md!(v5s; "propBytes", 1, vec![s.clone()], col_byte(),        vec![]),
            md!(v5s; "isProven",  2, vec![s.clone()], SType::SBoolean,   vec![]),
        ]
    })
}

// SOption (type_id = 36): methods.scala:727-803.
// ids 1, 5, 6 are absent.
// isDefined/get/getOrElse: custom irBuilders (→ OptionIsDefined/OptionGet/OptionGetOrElse).
// map/filter: MethodCallIrBuilder.
// tpe_params: T appears in dom[0] SOption(T) and range; R in map.
fn option_methods() -> &'static Vec<SMethodDesc> {
    static METHODS: OnceLock<Vec<SMethodDesc>> = OnceLock::new();
    METHODS.get_or_init(|| {
        let t = tv("T");
        let r = tv("R");
        let this = sopt(t.clone());
        let func_t_r = SType::SFunc {
            dom: vec![t.clone()],
            range: Box::new(r.clone()),
        };
        let func_t_bool = SType::SFunc {
            dom: vec![t.clone()],
            range: Box::new(SType::SBoolean),
        };
        vec![
            // id 1 absent
            // isDefined/get: Scala tpeParams=Nil (methods.scala:750/:758 — 2-arg SFunc;
            // T is bound from the receiver SOption(T) via specialize_for unification).
            md!(v5; "isDefined",  2, vec![this.clone()],                           SType::SBoolean,    vec![]),
            md!(v5; "get",        3, vec![this.clone()],                           t.clone(),          vec![]),
            md!(v5; "getOrElse",  4, vec![this.clone(), t.clone()],                t.clone(),          vec!["T".into()]),
            // ids 5, 6 absent
            md!(v5; "map",        7, vec![this.clone(), func_t_r],                 sopt(r.clone()),    vec!["T".into(), "R".into()]),
            md!(v5; "filter",     8, vec![this.clone(), func_t_bool],              this.clone(),       vec!["T".into()]),
        ]
    })
}

// SCollection (type_id = 12): methods.scala:805-1228.
// ThisType = SColl(IV), OV used in map/fold/zip/flatMap results.
// Absent ids: 11-13, 16-18, 22-25, 27-28.
// size (id 1): NO withIRInfo → Select → SizeOf.
// All others: custom irBuilders or MethodCallIrBuilder → MethodCall.
// flatMap (id 15): confirmed by golden seed.
// zip/indexOf/patch/updated/updateMany: confirmed by golden seed.
fn collection_methods() -> &'static Vec<SMethodDesc> {
    static METHODS: OnceLock<Vec<SMethodDesc>> = OnceLock::new();
    METHODS.get_or_init(|| {
        let iv = tv("IV");
        let ov = tv("OV");
        let this = scoll(iv.clone());
        let this_ov = scoll(ov.clone());
        let func_iv_ov = SType::SFunc {
            dom: vec![iv.clone()],
            range: Box::new(ov.clone()),
        };
        let func_iv_bool = SType::SFunc {
            dom: vec![iv.clone()],
            range: Box::new(SType::SBoolean),
        };
        let func_iv_coll_ov = SType::SFunc {
            dom: vec![iv.clone()],
            range: Box::new(scoll(ov.clone())),
        };
        let func_ov_iv_ov = SType::SFunc {
            dom: vec![ov.clone(), iv.clone()],
            range: Box::new(ov.clone()),
        };
        let zip_range = scoll(stup(vec![iv.clone(), ov.clone()]));
        vec![
            // id 1: NO withIRInfo → Select → SizeOf opcode 0xB1
            // size: Scala tpeParams=Nil (methods.scala:821 — 2-arg SFunc; IV bound from receiver).
            md!(v5s; "size",        1,  vec![this.clone()],                                    SType::SInt,     vec![]),
            md!(v5; "getOrElse",    2,  vec![this.clone(), SType::SInt, iv.clone()],           iv.clone(),      vec!["IV".into()]),
            md!(v5; "map",          3,  vec![this.clone(), func_iv_ov.clone()],                this_ov.clone(), vec!["IV".into(), "OV".into()]),
            md!(v5; "exists",       4,  vec![this.clone(), func_iv_bool.clone()],              SType::SBoolean, vec!["IV".into()]),
            md!(v5; "fold",         5,  vec![this.clone(), ov.clone(), func_ov_iv_ov.clone()], ov.clone(),      vec!["IV".into(), "OV".into()]),
            md!(v5; "forall",       6,  vec![this.clone(), func_iv_bool.clone()],              SType::SBoolean, vec!["IV".into()]),
            md!(v5; "slice",        7,  vec![this.clone(), SType::SInt, SType::SInt],          this.clone(),    vec!["IV".into()]),
            md!(v5; "filter",       8,  vec![this.clone(), func_iv_bool.clone()],              this.clone(),    vec!["IV".into()]),
            md!(v5; "append",       9,  vec![this.clone(), this.clone()],                      this.clone(),    vec!["IV".into()]),
            md!(v5; "apply",        10, vec![this.clone(), SType::SInt],                       iv.clone(),      vec!["IV".into()]),
            // ids 11-13 absent
            // indices: Scala tpeParams=Nil (methods.scala:954 — 2-arg SFunc; IV bound from receiver).
            md!(v5; "indices",      14, vec![this.clone()],                                    scoll(SType::SInt), vec![]),
            md!(v5; "flatMap",      15, vec![this.clone(), func_iv_coll_ov.clone()],           this_ov.clone(), vec!["IV".into(), "OV".into()]),
            // ids 16-18 absent
            md!(v5; "patch",        19, vec![this.clone(), SType::SInt, this.clone(), SType::SInt], this.clone(), vec!["IV".into()]),
            md!(v5; "updated",      20, vec![this.clone(), SType::SInt, iv.clone()],           this.clone(),    vec!["IV".into()]),
            md!(v5; "updateMany",   21, vec![this.clone(), scoll(SType::SInt), this.clone()],  this.clone(),    vec!["IV".into()]),
            // ids 22-25 absent
            md!(v5; "indexOf",      26, vec![this.clone(), iv.clone(), SType::SInt],           SType::SInt,     vec!["IV".into()]),
            // ids 27-28 absent
            md!(v5; "zip",          29, vec![this.clone(), this_ov.clone()],                   zip_range,       vec!["IV".into(), "OV".into()]),
            // V6 additions (ids 30-33)
            md!(v6; "reverse",      30, vec![this.clone()],                                    this.clone(),    vec!["IV".into()]),
            md!(v6; "startsWith",   31, vec![this.clone(), this.clone()],                      SType::SBoolean, vec!["IV".into()]),
            md!(v6; "endsWith",     32, vec![this.clone(), this.clone()],                      SType::SBoolean, vec!["IV".into()]),
            md!(v6; "get",          33, vec![this.clone(), SType::SInt],                       sopt(iv.clone()), vec!["IV".into()]),
        ]
    })
}

// STuple (type_id = 96): methods.scala:1231-1260.
// Only `size` (→ SizeOf) and `apply` (→ ByIndex) are stored here as base
// entries with SAny receiver.  Component accessors `_i` are synthesized
// dynamically in `get_tuple_component()` from the tuple's concrete items.
fn tuple_base_methods() -> &'static Vec<SMethodDesc> {
    static METHODS: OnceLock<Vec<SMethodDesc>> = OnceLock::new();
    METHODS.get_or_init(|| {
        // Receiver is SAny: matches any concrete tuple via unify Rule 11.
        vec![
            // size: NO withIRInfo (inherited from SCollection.size) → Select → SizeOf
            md!(v5s; "size",  1,  vec![SType::SAny],                 SType::SInt, vec![]),
            // apply: custom irBuilder → ByIndex; SAny range (runtime index)
            md!(v5; "apply",  10, vec![SType::SAny, SType::SInt],    SType::SAny, vec![]),
        ]
    })
}

// SBox (type_id = 99): methods.scala:1262-1380.
// value/propositionBytes/bytes/bytesWithoutRef/id/creationInfo/getRegV5/R0-R9:
//   NO withIRInfo → Select path.
// tokens (id 8): MethodCallIrBuilder → MethodCall.
// getReg (id 19, V6): MethodCallIrBuilder + wire explicit type arg.
// getRegV5 (id 7): internal Scala name; the user writes "getReg" but at V5 the
//   typer resolves id=7; id=19 is the V6 variant named "getReg".
fn box_methods() -> &'static Vec<SMethodDesc> {
    static METHODS: OnceLock<Vec<SMethodDesc>> = OnceLock::new();
    METHODS.get_or_init(|| {
        let b = SType::SBox;
        let t = tv("T");
        let opt_t = sopt(t.clone());
        let t_params = vec!["T".into()];
        // creationInfo return type: (Int, Coll[Byte])  (methods.scala:1321)
        let creation_info_tpe = stup(vec![SType::SInt, col_byte()]);
        // tokens return type: Coll[(Coll[Byte], Long)]  (ErgoBox.STokensRegType)
        let tokens_tpe = scoll(stup(vec![col_byte(), SType::SLong]));
        vec![
            md!(v5s; "value",            1,  vec![b.clone()],                  SType::SLong,        vec![]),
            md!(v5s; "propositionBytes", 2,  vec![b.clone()],                  col_byte(),          vec![]),
            md!(v5s; "bytes",            3,  vec![b.clone()],                  col_byte(),          vec![]),
            md!(v5s; "bytesWithoutRef",  4,  vec![b.clone()],                  col_byte(),          vec![]),
            md!(v5s; "id",               5,  vec![b.clone()],                  col_byte(),          vec![]),
            md!(v5s; "creationInfo",     6,  vec![b.clone()],                  creation_info_tpe,   vec![]),
            // getRegV5 (id 7): internal V5 variant; NO withIRInfo → Select path.
            // Caller passes a runtime SInt register id; return SOption(T).
            md!(v5s; "getRegV5",         7,  vec![b.clone(), SType::SInt],     opt_t.clone(),       t_params.clone()),
            // tokens (id 8): MethodCallIrBuilder → MethodCall
            md!(v5; "tokens",            8,  vec![b.clone()],                  tokens_tpe,          vec![]),
            // R0-R9 (ids 9-18): NO withIRInfo → Select path (register literals)
            md!(v5s; "R0", 9,  vec![b.clone()], opt_t.clone(), t_params.clone()),
            md!(v5s; "R1", 10, vec![b.clone()], opt_t.clone(), t_params.clone()),
            md!(v5s; "R2", 11, vec![b.clone()], opt_t.clone(), t_params.clone()),
            md!(v5s; "R3", 12, vec![b.clone()], opt_t.clone(), t_params.clone()),
            md!(v5s; "R4", 13, vec![b.clone()], opt_t.clone(), t_params.clone()),
            md!(v5s; "R5", 14, vec![b.clone()], opt_t.clone(), t_params.clone()),
            md!(v5s; "R6", 15, vec![b.clone()], opt_t.clone(), t_params.clone()),
            md!(v5s; "R7", 16, vec![b.clone()], opt_t.clone(), t_params.clone()),
            md!(v5s; "R8", 17, vec![b.clone()], opt_t.clone(), t_params.clone()),
            md!(v5s; "R9", 18, vec![b.clone()], opt_t.clone(), t_params.clone()),
            // getReg (id 19, V6): MethodCallIrBuilder + wire explicit type arg
            md!(v6e; "getReg",           19, vec![b.clone(), SType::SInt],     opt_t.clone(),       t_params),
        ]
    })
}

// SAvlTree (type_id = 100): methods.scala:1382-1726.
// ALL methods have MethodCallIrBuilder → MethodCall.
// Confirmed by golden seed §7: digest/keyLength/enabledOperations → MethodCall.
// CollKeyValue = SColl(STuple(Coll[Byte], Coll[Byte])).
// SByteArray2  = SColl(Coll[Byte]).
fn avl_tree_methods() -> &'static Vec<SMethodDesc> {
    static METHODS: OnceLock<Vec<SMethodDesc>> = OnceLock::new();
    METHODS.get_or_init(|| {
        let a = SType::SAvlTree;
        let cb = col_byte();
        let opt_a = sopt(a.clone());
        let opt_cb = sopt(cb.clone());
        let opt_int = sopt(SType::SInt);
        // CollKeyValue = SColl(STuple(Coll[B], Coll[B]))
        let kv = scoll(stup(vec![cb.clone(), cb.clone()]));
        // SByteArray2 = SColl(Coll[B])
        let arr2 = scoll(cb.clone());
        // SColl(SOption(Coll[B]))
        let coll_opt_cb = scoll(opt_cb.clone());
        vec![
            md!(v5; "digest",           1,  vec![a.clone()],                              cb.clone(),     vec![]),
            md!(v5; "enabledOperations",2,  vec![a.clone()],                              SType::SByte,   vec![]),
            md!(v5; "keyLength",        3,  vec![a.clone()],                              SType::SInt,    vec![]),
            md!(v5; "valueLengthOpt",   4,  vec![a.clone()],                              opt_int,        vec![]),
            md!(v5; "isInsertAllowed",  5,  vec![a.clone()],                              SType::SBoolean, vec![]),
            md!(v5; "isUpdateAllowed",  6,  vec![a.clone()],                              SType::SBoolean, vec![]),
            md!(v5; "isRemoveAllowed",  7,  vec![a.clone()],                              SType::SBoolean, vec![]),
            md!(v5; "updateOperations", 8,  vec![a.clone(), SType::SByte],                a.clone(),      vec![]),
            md!(v5; "contains",         9,  vec![a.clone(), cb.clone(), cb.clone()],      SType::SBoolean, vec![]),
            md!(v5; "get",              10, vec![a.clone(), cb.clone(), cb.clone()],      opt_cb.clone(), vec![]),
            md!(v5; "getMany",          11, vec![a.clone(), arr2.clone(), cb.clone()],    coll_opt_cb,    vec![]),
            md!(v5; "insert",           12, vec![a.clone(), kv.clone(), cb.clone()],      opt_a.clone(),  vec![]),
            md!(v5; "update",           13, vec![a.clone(), kv.clone(), cb.clone()],      opt_a.clone(),  vec![]),
            md!(v5; "remove",           14, vec![a.clone(), arr2.clone(), cb.clone()],    opt_a.clone(),  vec![]),
            md!(v5; "updateDigest",     15, vec![a.clone(), cb.clone()],                  a.clone(),      vec![]),
            // V6 addition
            md!(v6; "insertOrUpdate",   16, vec![a.clone(), kv.clone(), cb.clone()],      opt_a.clone(),  vec![]),
        ]
    })
}

// SContext (type_id = 101): methods.scala:1729-1791.
// dataInputs..minerPubKey (ids 1-10): MethodCallIrBuilder (PropertyCall shape).
// getVar (id 11): NO withIRInfo → Select path; uses GetVar opcode 0xE3.
// getVarFromInput (id 12, V6): MethodCallIrBuilder + wire explicit type arg.
fn context_methods() -> &'static Vec<SMethodDesc> {
    static METHODS: OnceLock<Vec<SMethodDesc>> = OnceLock::new();
    METHODS.get_or_init(|| {
        let ctx = SType::SContext;
        let coll_box = scoll(SType::SBox);
        let coll_header = scoll(SType::SHeader);
        let t = tv("T");
        let opt_t = sopt(t.clone());
        let t_params = vec!["T".into()];
        vec![
            md!(v5; "dataInputs",            1,  vec![ctx.clone()], coll_box.clone(),        vec![]),
            md!(v5; "headers",               2,  vec![ctx.clone()], coll_header,             vec![]),
            md!(v5; "preHeader",             3,  vec![ctx.clone()], SType::SPreHeader,       vec![]),
            md!(v5; "INPUTS",                4,  vec![ctx.clone()], coll_box.clone(),        vec![]),
            md!(v5; "OUTPUTS",               5,  vec![ctx.clone()], coll_box.clone(),        vec![]),
            md!(v5; "HEIGHT",                6,  vec![ctx.clone()], SType::SInt,             vec![]),
            md!(v5; "SELF",                  7,  vec![ctx.clone()], SType::SBox,             vec![]),
            md!(v5; "selfBoxIndex",          8,  vec![ctx.clone()], SType::SInt,             vec![]),
            md!(v5; "LastBlockUtxoRootHash", 9,  vec![ctx.clone()], SType::SAvlTree,         vec![]),
            md!(v5; "minerPubKey",           10, vec![ctx.clone()], col_byte(),              vec![]),
            // getVar: NO withIRInfo → Select; GetVar opcode path in lowering.
            // No wire explicit_type_args (uses GetVar opcode, not MethodCall wire).
            md!(v5s; "getVar",               11, vec![ctx.clone(), SType::SByte], opt_t.clone(), t_params.clone()),
            // getVarFromInput: V6, MethodCallIrBuilder + explicit type arg.
            md!(v6e; "getVarFromInput",      12, vec![ctx.clone(), SType::SShort, SType::SByte], opt_t.clone(), t_params),
        ]
    })
}

// SHeader (type_id = 104): methods.scala:1793-1835.
// All PropertyCall (MethodCallIrBuilder) except checkPow which is V6.
// checkPow confirmed: MethodCallIrBuilder → MethodCall.
fn header_methods() -> &'static Vec<SMethodDesc> {
    static METHODS: OnceLock<Vec<SMethodDesc>> = OnceLock::new();
    METHODS.get_or_init(|| {
        let h = SType::SHeader;
        let g = SType::SGroupElement;
        vec![
            md!(v5; "id",               1,  vec![h.clone()], col_byte(),     vec![]),
            md!(v5; "version",          2,  vec![h.clone()], SType::SByte,   vec![]),
            md!(v5; "parentId",         3,  vec![h.clone()], col_byte(),     vec![]),
            md!(v5; "ADProofsRoot",     4,  vec![h.clone()], col_byte(),     vec![]),
            md!(v5; "stateRoot",        5,  vec![h.clone()], SType::SAvlTree, vec![]),
            md!(v5; "transactionsRoot", 6,  vec![h.clone()], col_byte(),     vec![]),
            md!(v5; "timestamp",        7,  vec![h.clone()], SType::SLong,   vec![]),
            md!(v5; "nBits",            8,  vec![h.clone()], SType::SLong,   vec![]),
            md!(v5; "height",           9,  vec![h.clone()], SType::SInt,    vec![]),
            md!(v5; "extensionRoot",    10, vec![h.clone()], col_byte(),     vec![]),
            md!(v5; "minerPk",         11, vec![h.clone()], g.clone(),      vec![]),
            md!(v5; "powOnetimePk",    12, vec![h.clone()], g.clone(),      vec![]),
            md!(v5; "powNonce",        13, vec![h.clone()], col_byte(),     vec![]),
            md!(v5; "powDistance",     14, vec![h.clone()], SType::SBigInt, vec![]),
            md!(v5; "votes",           15, vec![h.clone()], col_byte(),     vec![]),
            md!(v6; "checkPow",        16, vec![h.clone()], SType::SBoolean, vec![]),
        ]
    })
}

// SPreHeader (type_id = 105): methods.scala:1837-1852.
// All V5, all PropertyCall (MethodCallIrBuilder).
fn pre_header_methods() -> &'static Vec<SMethodDesc> {
    static METHODS: OnceLock<Vec<SMethodDesc>> = OnceLock::new();
    METHODS.get_or_init(|| {
        let ph = SType::SPreHeader;
        vec![
            md!(v5; "version",   1, vec![ph.clone()], SType::SByte,      vec![]),
            md!(v5; "parentId",  2, vec![ph.clone()], col_byte(),         vec![]),
            md!(v5; "timestamp", 3, vec![ph.clone()], SType::SLong,       vec![]),
            md!(v5; "nBits",     4, vec![ph.clone()], SType::SLong,       vec![]),
            md!(v5; "height",    5, vec![ph.clone()], SType::SInt,        vec![]),
            md!(v5; "minerPk",   6, vec![ph.clone()], SType::SGroupElement, vec![]),
            md!(v5; "votes",     7, vec![ph.clone()], col_byte(),         vec![]),
        ]
    })
}

// SGlobal (type_id = 106): methods.scala:1854-2022.
// V5 registry: ids 1-2.  V6 adds: ids 3-10.
// groupGenerator/xor: custom irBuilders (→ GroupGenerator/Xor).
// serialize (id 3): MethodCallIrBuilder; NO wire explicit_type_args (delta5).
// deserializeTo/fromBigEndianBytes/some/none: MethodCallIrBuilder + explicit.
// encodeNbits/decodeNbits/powHit: MethodCallIrBuilder, no explicit.
// powHit signature (delta2): (SGlobal, Int, Coll[B], Coll[B], Coll[B], Int) → UnsignedBigInt.
fn global_methods() -> &'static Vec<SMethodDesc> {
    static METHODS: OnceLock<Vec<SMethodDesc>> = OnceLock::new();
    METHODS.get_or_init(|| {
        let g = SType::SGlobal;
        let cb = col_byte();
        let t = tv("T");
        let opt_t = sopt(t.clone());
        let t_params = vec!["T".into()];
        vec![
            md!(v5; "groupGenerator",    1, vec![g.clone()],                              SType::SGroupElement, vec![]),
            md!(v5; "xor",               2, vec![g.clone(), cb.clone(), cb.clone()],      cb.clone(),   vec![]),
            // V6 — serialize: NO wire explicit_type_args (delta5 in m2-tables.md)
            md!(v6; "serialize",         3, vec![g.clone(), t.clone()],                   cb.clone(),   t_params.clone()),
            md!(v6e; "deserializeTo",    4, vec![g.clone(), cb.clone()],                  t.clone(),    t_params.clone()),
            md!(v6e; "fromBigEndianBytes",5,vec![g.clone(), cb.clone()],                  t.clone(),    t_params.clone()),
            md!(v6; "encodeNbits",       6, vec![g.clone(), SType::SBigInt],              SType::SLong, vec![]),
            md!(v6; "decodeNbits",       7, vec![g.clone(), SType::SLong],               SType::SBigInt, vec![]),
            // powHit: k:Int, msg:Coll[B], nonce:Coll[B], h:Coll[B], N:Int → UnsignedBigInt
            md!(v6; "powHit",            8, vec![g.clone(), SType::SInt, cb.clone(), cb.clone(), cb.clone(), SType::SInt], SType::SUnsignedBigInt, vec![]),
            md!(v6e; "some",             9, vec![g.clone(), t.clone()],                   opt_t.clone(), t_params.clone()),
            md!(v6e; "none",             10,vec![g.clone()],                              opt_t.clone(), t_params),
        ]
    })
}

// Empty containers — recognized as SProduct types but have no methods.
// SBoolean, SString, SAny, SUnit.
fn empty_methods() -> &'static Vec<SMethodDesc> {
    static METHODS: OnceLock<Vec<SMethodDesc>> = OnceLock::new();
    METHODS.get_or_init(Vec::new)
}

// ─────────────────────────────────────────────────────────────────────────────
// STuple component synthesizer
// ─────────────────────────────────────────────────────────────────────────────

// Pre-allocated static names for tuple component accessors `_1` .. `_32`.
// Ergo tuples are bounded in practice; 32 covers all practical cases.
const TUPLE_COMPONENT_NAMES: [&str; 32] = [
    "_1", "_2", "_3", "_4", "_5", "_6", "_7", "_8", "_9", "_10", "_11", "_12", "_13", "_14", "_15",
    "_16", "_17", "_18", "_19", "_20", "_21", "_22", "_23", "_24", "_25", "_26", "_27", "_28",
    "_29", "_30", "_31", "_32",
];

/// Synthesize an `_i` tuple component descriptor on demand.
///
/// `name` must be of the form `_1`, `_2`, …, `_N` (1-based).
/// Returns `None` if the index is out of range or the name doesn't match.
fn get_tuple_component(items: &[SType], name: &str) -> Option<SMethodDesc> {
    let idx_str = name.strip_prefix('_')?;
    let idx: usize = idx_str.parse().ok()?;
    if idx == 0 || idx > items.len() || idx > TUPLE_COMPONENT_NAMES.len() {
        return None;
    }
    let range = items[idx - 1].clone();
    let recv = SType::STuple(items.to_vec());
    // `_i` accessors: NO withIRInfo (comparable to SBox property accessors).
    // Wire encoding uses SelectField opcode 0x8C (lowering handles this).
    Some(SMethodDesc {
        name: TUPLE_COMPONENT_NAMES[idx - 1],
        method_id: idx as u8,
        stype: SFuncSpec {
            dom: vec![recv],
            range,
            tpe_params: vec![],
        },
        has_ir_builder: false,
        explicit_type_args: false,
        min_version: 0,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal dispatch — map SType → static container vec
// ─────────────────────────────────────────────────────────────────────────────

fn container_static_methods(receiver: &SType) -> Option<&'static Vec<SMethodDesc>> {
    match receiver {
        SType::SByte => Some(byte_methods()),
        SType::SShort => Some(short_methods()),
        SType::SInt => Some(int_methods()),
        SType::SLong => Some(long_methods()),
        SType::SBigInt => Some(bigint_methods()),
        SType::SUnsignedBigInt => Some(unsigned_bigint_methods()),
        SType::SGroupElement => Some(group_element_methods()),
        SType::SSigmaProp => Some(sigma_prop_methods()),
        SType::SBox => Some(box_methods()),
        SType::SAvlTree => Some(avl_tree_methods()),
        SType::SContext => Some(context_methods()),
        SType::SHeader => Some(header_methods()),
        SType::SPreHeader => Some(pre_header_methods()),
        SType::SGlobal => Some(global_methods()),
        SType::SColl(_) => Some(collection_methods()),
        SType::SOption(_) => Some(option_methods()),
        SType::STuple(_) => Some(tuple_base_methods()),
        // Empty containers — recognized but have no methods
        SType::SBoolean | SType::SString | SType::SAny | SType::SUnit => Some(empty_methods()),
        _ => None,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────────────

/// Look up a method by name on `receiver` at the given ErgoTree version.
///
/// Returns `None` when:
/// - the receiver type has no method container (non-product type);
/// - the container is empty (SBoolean/SString/SAny/SUnit — use `container_exists`
///   to distinguish "empty container" from "no container");
/// - the method doesn't exist or requires a higher `min_version` than
///   `tree_version`.
///
/// For `STuple` receivers the `_i` component methods are synthesized dynamically
/// from the tuple's concrete item types.
pub fn get_method(receiver: &SType, name: &str, tree_version: u8) -> Option<SMethodDesc> {
    // Synthesize tuple component accessors on demand.
    if let SType::STuple(items) = receiver {
        if let Some(desc) = get_tuple_component(items, name) {
            if desc.min_version <= tree_version {
                return Some(desc);
            }
            return None;
        }
    }

    let methods = container_static_methods(receiver)?;
    methods
        .iter()
        .find(|m| m.name == name && m.min_version <= tree_version)
        .cloned()
}

/// True iff `receiver` has a method container (even if the container is empty).
///
/// Distinguishes "empty-but-product" types (SBoolean/SString/SAny/SUnit) —
/// which have containers but no methods — from non-product types (SFunc,
/// NoType, STypeVar, STypeApply) — which have no container at all.
///
/// In the typer: a `MethodNotFound` error is appropriate when `container_exists`
/// is true but `get_method` returns None; a `NonProductType` error applies when
/// `container_exists` is false.
///
/// **Version-independence deviation:** The Scala `MethodsContainer.contains` is
/// version-gated (methods.scala:171–181); this function is version-independent.
/// The deviation is inert in practice because the types that gain containers in V6
/// (`SUnsignedBigInt`, `SHeader` V6 additions) are unconstructable in pre-V6 trees
/// — the typer never reaches a method-lookup for them at `tree_version < 3`.
pub fn container_exists(receiver: &SType) -> bool {
    container_static_methods(receiver).is_some()
}

/// True iff `receiver` has a method named `name` accessible at `tree_version`.
pub fn has_method(receiver: &SType, name: &str, tree_version: u8) -> bool {
    get_method(receiver, name, tree_version).is_some()
}

/// Look up a SGlobal method by name at the given ErgoTree version.
///
/// Convenience wrapper over `get_method(&SType::SGlobal, name, tree_version)`.
pub fn global_method(name: &str, tree_version: u8) -> Option<SMethodDesc> {
    get_method(&SType::SGlobal, name, tree_version)
}

/// Specialize a method descriptor for a concrete receiver and argument types.
///
/// Unifies `desc.stype.dom` against `[obj_tpe] ++ arg_tpes`, then applies the
/// resulting `TypeSubst` to the method's `SFuncSpec` (substituting type
/// variables and dropping substituted `tpe_params`).
///
/// Returns `None` if the types are incompatible (unification fails).
///
/// **Deviation from Scala:** `SMethod.specializeFor` (methods.scala:193–199) returns
/// `this` (the unspecialized descriptor) on unification failure, silently accepting
/// a mismatch.  This implementation returns `None` instead, leaving the type error
/// to the caller — the typer raises it as a `TypeMismatch`.  The stricter behaviour
/// is correct for a frontend type-checker; the Scala leniency exists to preserve
/// IR round-trips through the evaluator.
pub fn specialize_for(
    desc: &SMethodDesc,
    obj_tpe: &SType,
    arg_tpes: &[SType],
) -> Option<SFuncSpec> {
    let mut actual_dom = Vec::with_capacity(1 + arg_tpes.len());
    actual_dom.push(obj_tpe.clone());
    actual_dom.extend_from_slice(arg_tpes);
    let subst = unify_type_lists(&desc.stype.dom, &actual_dom)?;
    Some(apply_subst_func(&desc.stype, &subst))
}

/// Owner name string used in the `%Owner.method` printed form of a MethodRef.
///
/// Matches the names used in `typed_print::to_term_string` and confirmed by
/// the golden seed (e.g. `%SigmaDslBuilder.serialize`, `%SCollection.zip`,
/// `%GroupElement.negate`, `%BigInt.toBytes`, `%AvlTree.digest`).
///
/// Returns `None` for types that cannot be method-call receivers (SFunc,
/// NoType, STypeVar, STypeApply).
pub fn owner_name_for_type(t: &SType) -> Option<&'static str> {
    match t {
        SType::SGlobal => Some("SigmaDslBuilder"),
        SType::SColl(_) => Some("SCollection"),
        SType::SBigInt => Some("BigInt"),
        SType::SGroupElement => Some("GroupElement"),
        SType::SAvlTree => Some("AvlTree"),
        SType::SBox => Some("Box"),
        SType::SContext => Some("Context"),
        SType::SHeader => Some("Header"),
        SType::SPreHeader => Some("PreHeader"),
        SType::SSigmaProp => Some("SigmaProp"),
        // SOption.typeName = getClass.getSimpleName → "SOption" (methods.scala:701, SType.scala:238-244).
        // Confirmed by live oracle: `getVar[Int](1).map(...)` → `%SOption.map` (golden_seed §9).
        SType::SOption(_) => Some("SOption"),
        SType::SByte => Some("Byte"),
        SType::SShort => Some("Short"),
        SType::SInt => Some("Int"),
        SType::SLong => Some("Long"),
        SType::SUnsignedBigInt => Some("UnsignedBigInt"),
        // STuple.typeName = getClass.getSimpleName → "STuple" (methods.scala:833, SType.scala:238-244).
        SType::STuple(_) => Some("STuple"),
        SType::SBoolean => Some("Boolean"),
        _ => None,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ----- helpers -----

    /// All non-empty containers (type, expected method count at V6).
    /// Count = number of unique method_id slots (not all ids are contiguous).
    fn all_non_empty_containers_v6() -> Vec<(&'static str, SType, usize)> {
        vec![
            ("SByte", SType::SByte, 13),
            ("SShort", SType::SShort, 13),
            ("SInt", SType::SInt, 13),
            ("SLong", SType::SLong, 13),
            ("SBigInt", SType::SBigInt, 15),
            ("SUnsignedBigInt", SType::SUnsignedBigInt, 19),
            ("SGroupElement", SType::SGroupElement, 5),
            ("SSigmaProp", SType::SSigmaProp, 2),
            ("SOption", SType::SOption(Box::new(SType::SAny)), 5),
            ("SCollection", SType::SColl(Box::new(SType::SAny)), 21),
            ("STuple", SType::STuple(vec![SType::SInt, SType::SByte]), 2), // base only
            // value(1)+propositionBytes(2)+bytes(3)+bytesWithoutRef(4)+id(5)
            // +creationInfo(6)+getRegV5(7)+tokens(8)+R0-R9(9-18)+getReg(19) = 19
            ("SBox", SType::SBox, 19),
            ("SAvlTree", SType::SAvlTree, 16),
            ("SContext", SType::SContext, 12),
            ("SHeader", SType::SHeader, 16),
            ("SPreHeader", SType::SPreHeader, 7),
            ("SGlobal", SType::SGlobal, 10),
        ]
    }

    // ----- happy path — container counts -----

    #[test]
    fn per_container_method_counts_at_v6() {
        for (name, stype, expected) in all_non_empty_containers_v6() {
            let methods =
                container_static_methods(&stype).unwrap_or_else(|| panic!("{name}: no container"));
            assert_eq!(
                methods.len(),
                expected,
                "{name}: expected {expected} methods, got {}",
                methods.len()
            );
        }
    }

    #[test]
    fn empty_containers_have_no_methods() {
        for stype in [SType::SBoolean, SType::SString, SType::SAny, SType::SUnit] {
            let methods = container_static_methods(&stype).unwrap();
            assert!(methods.is_empty(), "{stype:?}: expected empty methods vec");
        }
    }

    #[test]
    fn non_product_types_have_no_container() {
        for stype in [
            SType::NoType,
            SType::STypeVar("T".into()),
            SType::SFunc {
                dom: vec![SType::SInt],
                range: Box::new(SType::SByte),
            },
        ] {
            assert!(
                container_static_methods(&stype).is_none(),
                "{stype:?}: should have no container"
            );
        }
    }

    // ----- happy path — container_exists -----

    #[test]
    fn container_exists_for_product_types() {
        // Non-empty containers
        assert!(container_exists(&SType::SByte));
        assert!(container_exists(&SType::SBox));
        assert!(container_exists(&SType::SColl(Box::new(SType::SInt))));
        assert!(container_exists(&SType::STuple(vec![SType::SInt])));
        // Empty containers (product but no methods)
        assert!(container_exists(&SType::SBoolean));
        assert!(container_exists(&SType::SUnit));
        assert!(container_exists(&SType::SAny));
        assert!(container_exists(&SType::SString));
    }

    #[test]
    fn container_exists_false_for_non_product() {
        assert!(!container_exists(&SType::NoType));
        assert!(!container_exists(&SType::STypeVar("X".into())));
        assert!(!container_exists(&SType::SFunc {
            dom: vec![SType::SInt],
            range: Box::new(SType::SInt),
        }));
    }

    // ----- happy path — version gating -----

    #[test]
    fn v6_only_methods_absent_at_tree_version_2() {
        // fromBigEndianBytes/deserializeTo/none confirmed V6-gated by golden seed §6
        assert!(get_method(&SType::SGlobal, "fromBigEndianBytes", 2).is_none());
        assert!(get_method(&SType::SGlobal, "deserializeTo", 2).is_none());
        assert!(get_method(&SType::SGlobal, "none", 2).is_none());
        // bitwiseInverse is a V6 numeric method
        assert!(get_method(&SType::SInt, "bitwiseInverse", 2).is_none());
        // checkPow is V6
        assert!(get_method(&SType::SHeader, "checkPow", 2).is_none());
        // insertOrUpdate is V6
        assert!(get_method(&SType::SAvlTree, "insertOrUpdate", 2).is_none());
        // SCollection.reverse is V6
        assert!(get_method(&SType::SColl(Box::new(SType::SInt)), "reverse", 2).is_none());
    }

    #[test]
    fn v6_only_methods_present_at_tree_version_3() {
        // All three from golden seed §6 should appear at V6
        assert!(get_method(&SType::SGlobal, "fromBigEndianBytes", 3).is_some());
        assert!(get_method(&SType::SGlobal, "deserializeTo", 3).is_some());
        assert!(get_method(&SType::SGlobal, "none", 3).is_some());
        assert!(get_method(&SType::SInt, "bitwiseInverse", 3).is_some());
        assert!(get_method(&SType::SHeader, "checkPow", 3).is_some());
    }

    #[test]
    fn v5_methods_present_at_tree_version_2() {
        assert!(get_method(&SType::SGlobal, "groupGenerator", 2).is_some());
        assert!(get_method(&SType::SGlobal, "xor", 2).is_some());
        assert!(get_method(&SType::SBox, "value", 2).is_some());
        assert!(get_method(&SType::SGroupElement, "negate", 2).is_some());
        assert!(get_method(&SType::SAvlTree, "digest", 2).is_some());
    }

    // ----- happy path — has_ir_builder cross-check vs golden seed -----

    /// Every MethodCall survivor in golden seed §4 must have has_ir_builder=true.
    #[test]
    fn golden_seed_method_call_survivors_have_ir_builder() {
        // §4 confirmed survivors — all must produce MethodCall (has_ir_builder=true).
        let cases: &[(&SType, &str)] = &[
            (&SType::SGlobal, "serialize"),
            (&SType::SGlobal, "some"),
            (&SType::SGlobal, "none"),
            (&SType::SGlobal, "fromBigEndianBytes"),
            (&SType::SGlobal, "deserializeTo"),
            (&SType::SGroupElement, "negate"),
            (&SType::SBigInt, "toBytes"),
            (&SType::SAvlTree, "digest"),
            (&SType::SAvlTree, "keyLength"),
            (&SType::SAvlTree, "enabledOperations"),
        ];
        let coll_long = SType::SColl(Box::new(SType::SLong));
        let coll_cases: &[(&SType, &str)] = &[
            (&coll_long, "zip"),
            (&coll_long, "indexOf"),
            (&coll_long, "flatMap"),
            (&coll_long, "patch"),
            (&coll_long, "updated"),
            (&coll_long, "updateMany"),
        ];

        for (recv, name) in cases.iter().chain(coll_cases) {
            let desc = get_method(recv, name, 3)
                .unwrap_or_else(|| panic!("method {name} on {recv:?} not found"));
            assert!(
                desc.has_ir_builder,
                "method {name} on {recv:?}: expected has_ir_builder=true (seed shows MethodCall)"
            );
        }
    }

    /// Methods that produce Select nodes (confirmed by golden seed §2) must have
    /// has_ir_builder=false.
    #[test]
    fn select_path_methods_have_no_ir_builder() {
        // `1.toByte + 2.toByte` → Select:Byte (seed §2: cast methods are Select)
        for recv in [
            SType::SByte,
            SType::SShort,
            SType::SInt,
            SType::SLong,
            SType::SBigInt,
        ] {
            for name in ["toByte", "toShort", "toInt", "toLong", "toBigInt"] {
                if let Some(desc) = get_method(&recv, name, 3) {
                    assert!(
                        !desc.has_ir_builder,
                        "cast method {name} on {recv:?} should have has_ir_builder=false"
                    );
                }
            }
        }
        // `b.value → Select:Long` (seed §1)
        let value = get_method(&SType::SBox, "value", 3).unwrap();
        assert!(!value.has_ir_builder, "SBox.value should be Select path");

        // SCollection.size → SizeOf via Select (no irBuilder)
        let size = get_method(&SType::SColl(Box::new(SType::SInt)), "size", 3).unwrap();
        assert!(
            !size.has_ir_builder,
            "SCollection.size should be Select path"
        );

        // SSigmaProp.propBytes/isProven — no withIRInfo
        let prop = get_method(&SType::SSigmaProp, "propBytes", 3).unwrap();
        assert!(
            !prop.has_ir_builder,
            "SSigmaProp.propBytes should be Select path"
        );
        let is_proven = get_method(&SType::SSigmaProp, "isProven", 3).unwrap();
        assert!(
            !is_proven.has_ir_builder,
            "SSigmaProp.isProven should be Select path"
        );

        // SContext.getVar — no withIRInfo
        let get_var = get_method(&SType::SContext, "getVar", 3).unwrap();
        assert!(
            !get_var.has_ir_builder,
            "SContext.getVar should be Select path"
        );
    }

    // ----- happy path — explicit_type_args -----

    #[test]
    fn explicit_type_args_correct_for_known_set() {
        // Exactly 6 methods have wire explicit_type_args.
        // Source: ergo-ser method_explicit_type_args_count + m2-tables.md §coverage.
        let explicit_set: &[(&SType, &str)] = &[
            (&SType::SBox, "getReg"),                // (99,19)
            (&SType::SContext, "getVarFromInput"),   // (101,12)
            (&SType::SGlobal, "deserializeTo"),      // (106,4)
            (&SType::SGlobal, "fromBigEndianBytes"), // (106,5)
            (&SType::SGlobal, "some"),               // (106,9)
            (&SType::SGlobal, "none"),               // (106,10)
        ];
        for (recv, name) in explicit_set {
            let desc =
                get_method(recv, name, 3).unwrap_or_else(|| panic!("{name} on {recv:?} not found"));
            assert!(
                desc.explicit_type_args,
                "{name} on {recv:?} should have explicit_type_args=true"
            );
        }

        // serialize (106,3) is explicitly excluded per delta5
        let ser = get_method(&SType::SGlobal, "serialize", 3).unwrap();
        assert!(
            !ser.explicit_type_args,
            "serialize must NOT have explicit_type_args"
        );

        // No non-SGlobal/SBox/SContext method should have explicit_type_args
        for (_, stype, _) in all_non_empty_containers_v6() {
            if matches!(stype, SType::SBox | SType::SContext | SType::SGlobal) {
                continue;
            }
            if let Some(methods) = container_static_methods(&stype) {
                for m in methods {
                    assert!(
                        !m.explicit_type_args,
                        "{:?}.{} should not have explicit_type_args",
                        stype, m.name
                    );
                }
            }
        }
    }

    // ----- happy path — specialize_for -----

    #[test]
    fn specialize_for_scoll_zip_long_long() {
        // col1.zip(col2) where col1, col2: Coll[Long]
        // Expected result: dom=[Coll[Long],Coll[Long]], range=Coll[(Long,Long)]
        let coll_long = SType::SColl(Box::new(SType::SLong));
        let desc = get_method(&coll_long, "zip", 3).unwrap();
        let spec = specialize_for(&desc, &coll_long, std::slice::from_ref(&coll_long)).unwrap();
        assert_eq!(spec.dom[0], coll_long);
        assert_eq!(spec.dom[1], coll_long);
        assert_eq!(
            spec.range,
            SType::SColl(Box::new(SType::STuple(vec![SType::SLong, SType::SLong])))
        );
        assert!(
            spec.tpe_params.is_empty(),
            "all type vars should be substituted"
        );
    }

    #[test]
    fn specialize_for_scoll_index_of_int() {
        // Coll[Int].indexOf(1, 0): dom=[Coll[Int], Int, Int], range=Int
        let coll_int = SType::SColl(Box::new(SType::SInt));
        let desc = get_method(&coll_int, "indexOf", 3).unwrap();
        let spec = specialize_for(&desc, &coll_int, &[SType::SInt, SType::SInt]).unwrap();
        assert_eq!(spec.dom[0], coll_int);
        assert_eq!(spec.range, SType::SInt);
        assert!(spec.tpe_params.is_empty());
    }

    #[test]
    fn specialize_for_sglobal_some_int() {
        // Global.some[Int](1): obj=SGlobal, arg=Int → range=Option[Int]
        let desc = get_method(&SType::SGlobal, "some", 3).unwrap();
        let spec = specialize_for(&desc, &SType::SGlobal, &[SType::SInt]).unwrap();
        assert_eq!(spec.range, SType::SOption(Box::new(SType::SInt)));
        assert!(spec.tpe_params.is_empty(), "T should be substituted to Int");
    }

    #[test]
    fn specialize_for_sglobal_none_int() {
        // Global.none[Int](): obj=SGlobal, no args, type arg Int → range=Option[Int]
        // specialize_for unifies dom=[SGlobal] against [SGlobal]; then T must be
        // inferred from context (explicit type arg). Range stays SOption(T) if T
        // isn't in the dom — this is expected; the typer applies the type arg externally.
        let desc = get_method(&SType::SGlobal, "none", 3).unwrap();
        let spec = specialize_for(&desc, &SType::SGlobal, &[]).unwrap();
        // T is not in dom (none takes only SGlobal), so subst is empty → range stays SOption(T)
        assert!(
            matches!(spec.range, SType::SOption(ref inner) if matches!(inner.as_ref(), SType::STypeVar(_))),
            "none() range should remain SOption(T) until explicit type arg is applied"
        );
    }

    #[test]
    fn specialize_for_numeric_byte_to_int() {
        // (1:SByte).toInt: concrete dom, no type vars → range=SInt
        let desc = get_method(&SType::SByte, "toInt", 3).unwrap();
        let spec = specialize_for(&desc, &SType::SByte, &[]).unwrap();
        assert_eq!(spec.range, SType::SInt);
        assert!(!spec.dom.is_empty());
        assert_eq!(spec.dom[0], SType::SByte);
    }

    #[test]
    fn specialize_for_soption_get_int() {
        // Option[Int].get: dom=[Option[Int]], range=Int
        let opt_int = SType::SOption(Box::new(SType::SInt));
        let desc = get_method(&opt_int, "get", 3).unwrap();
        let spec = specialize_for(&desc, &opt_int, &[]).unwrap();
        assert_eq!(spec.range, SType::SInt);
        assert!(spec.tpe_params.is_empty());
    }

    // ----- happy path — STuple component synthesis -----

    #[test]
    fn tuple_component_synthesized_correctly() {
        let tup = SType::STuple(vec![SType::SInt, SType::SByte, SType::SLong]);
        // _1 → SInt, method_id=1
        let d1 = get_method(&tup, "_1", 0).unwrap();
        assert_eq!(d1.method_id, 1);
        assert_eq!(d1.stype.range, SType::SInt);
        assert!(!d1.has_ir_builder);
        assert_eq!(d1.min_version, 0);
        // _3 → SLong
        let d3 = get_method(&tup, "_3", 0).unwrap();
        assert_eq!(d3.method_id, 3);
        assert_eq!(d3.stype.range, SType::SLong);
        // Out of range → None
        assert!(get_method(&tup, "_4", 0).is_none());
        assert!(get_method(&tup, "_0", 0).is_none());
    }

    #[test]
    fn tuple_size_and_apply_accessible() {
        let tup = SType::STuple(vec![SType::SInt, SType::SByte]);
        let size = get_method(&tup, "size", 0).unwrap();
        assert_eq!(size.method_id, 1);
        assert!(!size.has_ir_builder); // Select → SizeOf
        let apply = get_method(&tup, "apply", 0).unwrap();
        assert_eq!(apply.method_id, 10);
        assert!(apply.has_ir_builder); // custom irBuilder → ByIndex
    }

    // ----- happy path — global_method convenience -----

    #[test]
    fn global_method_serialize_v6() {
        let desc = global_method("serialize", 3).unwrap();
        assert_eq!(desc.method_id, 3);
        assert!(!desc.explicit_type_args);
        assert!(desc.has_ir_builder);
    }

    #[test]
    fn global_method_absent_below_min_version() {
        assert!(global_method("serialize", 2).is_none());
    }

    // ----- happy path — method_id assignments match ergo-ser -----

    /// Cross-check: every method in non-numeric containers (where ergo-ser has
    /// explicit type_id ranges) is recognized by ergo-ser's is_v6_method.
    ///
    /// This proves our method_id assignments agree with the wire codec.
    /// Numeric concrete types (2-9) are handled separately below since
    /// ergo-ser's is_v5_method omits them (MethodCall is V6-only for numerics).
    #[test]
    fn ergo_ser_v6_id_agreement() {
        use ergo_ser::opcode::{is_v5_method, is_v6_method};

        // (type_id, SType) pairs for containers tracked by ergo-ser
        let non_numeric: &[(u8, SType)] = &[
            (7, SType::SGroupElement),
            (8, SType::SSigmaProp),
            (12, SType::SColl(Box::new(SType::SAny))),
            (36, SType::SOption(Box::new(SType::SAny))),
            (99, SType::SBox),
            (100, SType::SAvlTree),
            (101, SType::SContext),
            (104, SType::SHeader),
            (105, SType::SPreHeader),
            (106, SType::SGlobal),
        ];
        for (type_id, stype) in non_numeric {
            let methods = container_static_methods(stype).unwrap();
            for m in methods {
                assert!(
                    is_v6_method(*type_id, m.method_id),
                    "type_id={type_id} method_id={} name={} not in ergo-ser is_v6_method",
                    m.method_id,
                    m.name
                );
            }
        }

        // Check V5 subset for the non-numeric containers
        for (type_id, stype) in non_numeric {
            let methods = container_static_methods(stype).unwrap();
            for m in methods.iter().filter(|m| m.min_version == 0) {
                assert!(
                    is_v5_method(*type_id, m.method_id),
                    "type_id={type_id} method_id={} name={} has min_version=0 but not in ergo-ser is_v5_method",
                    m.method_id, m.name
                );
            }
        }

        // Numeric concrete types: only V6 MethodCall is tracked (type_ids 2-6, 9)
        let numeric: &[(u8, SType)] = &[
            (2, SType::SByte),
            (3, SType::SShort),
            (4, SType::SInt),
            (5, SType::SLong),
            (6, SType::SBigInt),
            (9, SType::SUnsignedBigInt),
        ];
        for (type_id, stype) in numeric {
            let methods = container_static_methods(stype).unwrap();
            for m in methods {
                assert!(
                    is_v6_method(*type_id, m.method_id),
                    "type_id={type_id} method_id={} name={} not in ergo-ser is_v6_method",
                    m.method_id,
                    m.name
                );
            }
        }
    }

    // ----- happy path — SFuncSpec convenience methods -----

    #[test]
    fn sfunc_spec_dom_tail_and_is_nullary() {
        // toBytes is nullary (dom=[recv], no tpe_params)
        let to_bytes = get_method(&SType::SBigInt, "toBytes", 3).unwrap();
        assert!(to_bytes.stype.is_nullary());
        assert!(to_bytes.stype.dom_tail().is_empty());

        // bitwiseOr has one argument after receiver
        let bor = get_method(&SType::SInt, "bitwiseOr", 3).unwrap();
        assert!(!bor.stype.is_nullary());
        assert_eq!(bor.stype.dom_tail(), &[SType::SInt]);
    }

    #[test]
    fn sfunc_spec_with_receiver_type() {
        let negate = get_method(&SType::SGroupElement, "negate", 3).unwrap();
        let new_spec = negate.stype.with_receiver_type(SType::SGroupElement);
        assert_eq!(new_spec.dom[0], SType::SGroupElement);
        assert_eq!(new_spec.range, SType::SGroupElement);
    }

    // ----- oracle parity -----

    /// Oracle-grounded owner name for SOption.
    ///
    /// golden_seed §9: `getVar[Int](1).map(...)` → `%SOption.map`.
    /// Confirms that `owner_name_for_type(SOption(_))` must return `"SOption"`,
    /// not `"Option"`.  The Scala source is `STypeCompanion.typeName =
    /// getClass.getSimpleName` (SType.scala:238-244); the companion object at
    /// methods.scala:701 is `SOption`, so its `getSimpleName` is `"SOption"`.
    #[test]
    fn owner_name_soption_oracle_grounded() {
        // The oracle printed `%SOption.map` — owner substring is "SOption".
        let name = owner_name_for_type(&SType::SOption(Box::new(SType::SInt)));
        assert_eq!(
            name,
            Some("SOption"),
            "owner must match oracle output %SOption.map (golden_seed §9)"
        );
    }

    /// STuple owner name follows the same getSimpleName rule (methods.scala:833).
    #[test]
    fn owner_name_stuple_matches_type_name() {
        let name = owner_name_for_type(&SType::STuple(vec![SType::SInt, SType::SByte]));
        assert_eq!(
            name,
            Some("STuple"),
            "STuple.typeName = getSimpleName = \"STuple\" (methods.scala:833)"
        );
    }

    /// Verify the method_id of every container aligns with Scala's methods.scala.
    /// Uses known spot checks against the methods.scala line references in m2-tables.md.
    #[test]
    fn oracle_parity_spot_check_method_ids() {
        // SBox.tokens is id=8 (not 7 or 9)
        let tokens = get_method(&SType::SBox, "tokens", 3).unwrap();
        assert_eq!(tokens.method_id, 8);
        assert!(tokens.has_ir_builder);

        // SBox.getReg is id=19 (V6) — NOT 7 (that's getRegV5)
        let get_reg = get_method(&SType::SBox, "getReg", 3).unwrap();
        assert_eq!(get_reg.method_id, 19);
        assert!(get_reg.explicit_type_args);

        // SBigInt.toUnsigned is id=14 (NOT 8 — that's a stale comment in methods.scala:545)
        let to_unsigned = get_method(&SType::SBigInt, "toUnsigned", 3).unwrap();
        assert_eq!(to_unsigned.method_id, 14);

        // SOption: ids 1, 5, 6 are absent
        assert!(get_method(&SType::SOption(Box::new(SType::SAny)), "nonExistentId1", 3).is_none());
        let opt = SType::SOption(Box::new(SType::SAny));
        // ids actually present: 2,3,4,7,8
        assert!(get_method(&opt, "isDefined", 3).map(|m| m.method_id) == Some(2));
        assert!(get_method(&opt, "get", 3).map(|m| m.method_id) == Some(3));
        assert!(get_method(&opt, "getOrElse", 3).map(|m| m.method_id) == Some(4));
        assert!(get_method(&opt, "map", 3).map(|m| m.method_id) == Some(7));
        assert!(get_method(&opt, "filter", 3).map(|m| m.method_id) == Some(8));

        // SGlobal.powHit is id=8 (delta2 — correct return type is UnsignedBigInt)
        let pow_hit = global_method("powHit", 3).unwrap();
        assert_eq!(pow_hit.method_id, 8);
        assert_eq!(pow_hit.stype.range, SType::SUnsignedBigInt);

        // SContext.getVarFromInput is id=12 (V6) with explicit type args
        let gvfi = get_method(&SType::SContext, "getVarFromInput", 3).unwrap();
        assert_eq!(gvfi.method_id, 12);
        assert!(gvfi.explicit_type_args);
        assert_eq!(gvfi.min_version, 3);

        // SGroupElement: id 1 is absent; negate=5, expUnsigned=6 (V6)
        assert!(get_method(&SType::SGroupElement, "getEncoded", 3).map(|m| m.method_id) == Some(2));
        assert!(get_method(&SType::SGroupElement, "negate", 3).map(|m| m.method_id) == Some(5));
        assert!(
            get_method(&SType::SGroupElement, "expUnsigned", 3).map(|m| m.method_id) == Some(6)
        );

        // SAvlTree.insertOrUpdate is id=16 (V6)
        let iou = get_method(&SType::SAvlTree, "insertOrUpdate", 3).unwrap();
        assert_eq!(iou.method_id, 16);
        assert_eq!(iou.min_version, 3);

        // SHeader.checkPow is id=16 (V6)
        let cp = get_method(&SType::SHeader, "checkPow", 3).unwrap();
        assert_eq!(cp.method_id, 16);
        assert_eq!(cp.min_version, 3);
    }
}
