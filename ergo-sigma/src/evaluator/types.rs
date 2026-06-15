use ergo_primitives::cost::{CostError, JitCostError};
use ergo_ser::opcode::Expr;
use ergo_ser::register::RegisterValue;
use ergo_ser::sigma_type::SigmaType;
use ergo_ser::sigma_value::SigmaBoolean;
use num_traits::Zero;
use thiserror::Error;

/// Box representation for evaluation — covers both inputs and outputs.
///
/// Registers are stored as raw `RegisterValue` (type + sigma value) and
/// converted to evaluator `Value` lazily on access via `sigma_to_value`.
#[derive(Debug, Clone)]
pub struct EvalBox {
    /// Block height at which the box was created (R3 creationInfo).
    pub creation_height: u32,
    /// Canonical ErgoTree wire bytes of the locking script.
    pub script_bytes: Vec<u8>,
    /// Box value in nanoErg.
    pub value: i64,
    /// 32-byte box identifier (`Blake2b256` of the canonical box bytes).
    pub id: [u8; 32],
    /// Transaction ID that created this box (for R3 creationInfo).
    pub transaction_id: [u8; 32],
    /// Output index within the creating transaction (for R3 creationInfo).
    pub output_index: u16,
    /// Registers R4-R9. Index 0 = R4, index 5 = R9.
    /// Stored as raw (type, value) pairs; converted lazily on access.
    pub registers: [Option<RegisterValue>; 6],
    /// Token collection: (token_id, amount) pairs.
    pub tokens: Vec<([u8; 32], u64)>,
    /// Full serialized box bytes for ExtractBytes (0xC3).
    /// Populated from ErgoBox at construction; empty for test-only boxes.
    pub raw_bytes: Vec<u8>,
}

impl EvalBox {
    /// Test helper — creates a box with zero value and empty fields.
    /// Not valid for consensus (violates min box value).
    pub fn simple(creation_height: u32, script_bytes: Vec<u8>) -> Self {
        Self {
            creation_height,
            script_bytes,
            value: 0,
            id: [0u8; 32],
            transaction_id: [0u8; 32],
            output_index: 0,
            registers: [None, None, None, None, None, None],
            tokens: Vec::new(),
            raw_bytes: Vec::new(),
        }
    }
}

/// secp256k1 generator point in SEC1 compressed form (33 bytes).
/// Used by `0x82 GroupGenerator`, `SGlobal.groupGenerator` method,
/// and the `AutolykosSolution::V2` `pow_onetime_pk` default.
pub const SECP256K1_GENERATOR: [u8; 33] = [
    0x02, 0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B,
    0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17,
    0x98,
];

/// Header representation for SHeader property access in the evaluator.
///
/// Pre-extracted from `ergo_ser::header::Header` so the evaluator does not
/// depend on serialization internals. V1/V2 solution differences are
/// resolved at construction time.
#[derive(Debug, Clone, PartialEq)]
pub struct EvalHeader {
    /// 32-byte header identifier.
    pub id: [u8; 32],
    /// Header layout version.
    pub version: u8,
    /// Identifier of the previous block's header.
    pub parent_id: [u8; 32],
    /// Merkle root over the block's AD proofs section.
    pub ad_proofs_root: [u8; 32],
    /// AVL+ root of the post-block UTXO state (32 hash bytes + 1 height byte).
    pub state_root: [u8; 33],
    /// Merkle root over the block's transactions.
    pub transactions_root: [u8; 32],
    /// Block timestamp, milliseconds since the Unix epoch.
    pub timestamp: u64,
    /// Compact difficulty target (`nBits`).
    pub n_bits: u32,
    /// Block height.
    pub height: u32,
    /// Merkle root over the extension key-value section.
    pub extension_root: [u8; 32],
    /// Miner public key (SEC1-compressed secp256k1 point).
    pub miner_pk: [u8; 33],
    /// Per-block one-time PoW public key (Autolykos v1 `w`; v2 = generator).
    pub pow_onetime_pk: [u8; 33],
    /// 8-byte mining nonce.
    pub pow_nonce: [u8; 8],
    /// PoW distance (Autolykos v1 `d`; v2 = 0).
    pub pow_distance: num_bigint::BigInt,
    /// Three-byte miner vote vector for protocol parameter changes.
    pub votes: [u8; 3],
    /// Forward-compatible trailing bytes between the votes vector
    /// and the PoW solution (header v5+). Empty for v1-v4 per
    /// `ergo_ser::header::check_header_bounds`. Carried here so the
    /// v6 `SHeader.checkPow` method can re-serialize the header
    /// without losing data — `bytesWithoutPow → blake2b256` is the
    /// PoW message hash, and dropping these bytes would diverge
    /// from Scala for any v5+ header.
    pub unparsed_bytes: Vec<u8>,
}

impl EvalHeader {
    /// Build from a serialization-level Header + its computed header ID.
    pub fn from_header(h: &ergo_ser::header::Header, header_id: [u8; 32]) -> Self {
        let (pow_onetime_pk, pow_distance) = match &h.solution {
            ergo_ser::autolykos::AutolykosSolution::V1 { w, d, .. } => {
                let mut pk = [0u8; 33];
                pk.copy_from_slice(w.as_bytes());
                let dist = num_bigint::BigInt::from_signed_bytes_be(d);
                (pk, dist)
            }
            ergo_ser::autolykos::AutolykosSolution::V2 { .. } => {
                // V2: powOnetimePk = generator, powDistance = 0
                (SECP256K1_GENERATOR, num_bigint::BigInt::zero())
            }
        };
        let mut miner_pk = [0u8; 33];
        miner_pk.copy_from_slice(h.solution.pk().as_bytes());
        Self {
            id: header_id,
            version: h.version,
            parent_id: *h.parent_id.as_bytes(),
            ad_proofs_root: *h.ad_proofs_root.as_bytes(),
            state_root: *h.state_root.as_bytes(),
            transactions_root: *h.transactions_root.as_bytes(),
            timestamp: h.timestamp,
            n_bits: h.n_bits,
            height: h.height,
            extension_root: *h.extension_root.as_bytes(),
            miner_pk,
            pow_onetime_pk,
            pow_nonce: *h.solution.nonce(),
            pow_distance,
            votes: h.votes,
            unparsed_bytes: h.unparsed_bytes.clone(),
        }
    }

    /// Rebuild a serialization-layer [`ergo_ser::header::Header`] — the inverse
    /// of [`Self::from_header`]. The PoW solution variant is chosen by header
    /// version (v1 → Autolykos v1, v2+ → Autolykos v2). Used by
    /// `SHeader.checkPow` (re-hash) and `SGlobal.serialize[SHeader]` (re-emit).
    pub fn to_header(&self) -> ergo_ser::header::Header {
        use ergo_primitives::digest::{ADDigest, Digest32, ModifierId};
        use ergo_primitives::group_element::GroupElement;
        use ergo_ser::autolykos::AutolykosSolution;
        let pk = GroupElement::from_bytes(self.miner_pk);
        let solution = if self.version == 1 {
            AutolykosSolution::V1 {
                pk,
                w: GroupElement::from_bytes(self.pow_onetime_pk),
                nonce: self.pow_nonce,
                d: self.pow_distance.to_signed_bytes_be(),
            }
        } else {
            AutolykosSolution::V2 {
                pk,
                nonce: self.pow_nonce,
            }
        };
        ergo_ser::header::Header {
            version: self.version,
            parent_id: ModifierId::from_bytes(self.parent_id),
            ad_proofs_root: Digest32::from_bytes(self.ad_proofs_root),
            transactions_root: Digest32::from_bytes(self.transactions_root),
            state_root: ADDigest::from_bytes(self.state_root),
            timestamp: self.timestamp,
            extension_root: Digest32::from_bytes(self.extension_root),
            n_bits: self.n_bits,
            height: self.height,
            votes: self.votes,
            unparsed_bytes: self.unparsed_bytes.clone(),
            solution,
        }
    }
}

/// Evaluation context — borrows transaction-scoped box data.
///
/// All box collections are borrowed slices, not owned vectors.
/// This eliminates per-input cloning during script validation.
pub struct ReductionContext<'a> {
    /// Current block height (CONTEXT.HEIGHT).
    pub height: u32,
    /// The input box being spent — `None` only for non-spending evaluations.
    pub self_box: Option<&'a EvalBox>,
    /// `creation_height` of the box being spent. Carried separately
    /// because some scripts read it without otherwise referencing
    /// `self_box`.
    pub self_creation_height: u32,
    /// Outputs of the spending transaction (CONTEXT.OUTPUTS).
    pub outputs: &'a [EvalBox],
    /// All inputs of the spending transaction (CONTEXT.INPUTS).
    pub inputs: &'a [EvalBox],
    /// Read-only data inputs of the spending transaction (CONTEXT.dataInputs).
    pub data_inputs: &'a [EvalBox],
    /// SEC1-compressed miner public key for the containing block.
    pub miner_pubkey: [u8; 33],
    /// Pre-header timestamp (SPreHeader.timestamp).
    pub pre_header_timestamp: u64,
    /// Block version byte (SPreHeader.version).
    pub pre_header_version: u8,
    /// Parent block header ID (SPreHeader.parentId).
    pub pre_header_parent_id: [u8; 32],
    /// Encoded difficulty (SPreHeader.nBits).
    pub pre_header_n_bits: u64,
    /// Miner votes (SPreHeader.votes).
    pub pre_header_votes: [u8; 3],
    /// Context extension variables from the SELF input's spending
    /// proof. Keys are variable indices (0-255), values are typed
    /// Sigma constants. Backs `0xE3 GetVar` and the v6 method-call
    /// `SContext.getVar[T]`.
    pub extension: indexmap::IndexMap<
        u8,
        (
            ergo_ser::sigma_type::SigmaType,
            ergo_ser::sigma_value::SigmaValue,
        ),
    >,
    /// Extensions for every input of the spending transaction,
    /// indexed by input position. `input_extensions[i]` is the
    /// extension map carried by `tx.inputs[i].spending_proof`.
    /// Empty slice when not populated — the v6
    /// `SContext.getVarFromInput[T]` method falls back to
    /// `Opt(None)` in that case (preserves consensus correctness
    /// for synthetic test contexts that don't supply the data).
    pub input_extensions: &'a [indexmap::IndexMap<
        u8,
        (
            ergo_ser::sigma_type::SigmaType,
            ergo_ser::sigma_value::SigmaValue,
        ),
    >],
    /// Last 10 block headers for CONTEXT.headers (protocol-defined).
    /// Converted from serialization headers at the validation boundary.
    pub last_headers: &'a [EvalHeader],
    /// Pre-block UTXO state tree (CONTEXT.LastBlockUtxoRootHash, 0xA6).
    /// Scala `ErgoLikeContext` carries this as a first-class `AvlTreeData`
    /// (ErgoLikeContext.scala:48), populated at block-apply time via
    /// `ErgoInterpreter.avlTreeFromDigest(stateContext.previousStateDigest)`
    /// — digest from the prior block header, plus
    /// `AvlTreeFlags.AllOperationsAllowed`, `keyLength = 32`, no value
    /// length constraint. Metadata is NOT derivable from `last_headers`
    /// alone (the invariant only guarantees digest equality); populating
    /// a dedicated field matches mainnet behavior when scripts observe
    /// `enabledOperations`, `keyLength`, or `valueLengthOpt` on this tree.
    pub last_block_utxo_root: Option<ergo_ser::sigma_value::AvlTreeData>,
    /// Activated script version: block.headerVersion - 1.
    /// Controls consensus-preserving behavior differences across protocol versions.
    /// Pre-JIT (< 2): selfBoxIndex returns -1 (known bug preserved as consensus).
    pub activated_script_version: u8,
    /// ErgoTree HEADER version of the script under evaluation (the low 3 bits
    /// of the tree's header byte), NOT the activated/block version. Scala's
    /// `VersionContext.isV3OrLaterErgoTreeVersion` keys several v6 behaviors on
    /// THIS value, not on `activatedScriptVersion` — notably
    /// `DataSerializer.{de,}serialize(SHeader)`. Distinct because a legacy
    /// (version < 3) tree can be spent in a block whose activated version is
    /// already >= 3, and those two versions then disagree.
    pub ergo_tree_version: u8,
}

impl<'a> ReductionContext<'a> {
    /// Minimal context for scripts that only need HEIGHT and SELF.
    pub fn minimal(height: u32, self_creation_height: u32) -> Self {
        Self {
            height,
            self_box: None,
            self_creation_height,
            outputs: &[],
            inputs: &[],
            data_inputs: &[],
            miner_pubkey: [0u8; 33],
            pre_header_timestamp: 0,
            pre_header_version: 0,
            pre_header_parent_id: [0u8; 32],
            pre_header_n_bits: 0,
            pre_header_votes: [0u8; 3],
            extension: indexmap::IndexMap::new(),
            input_extensions: &[],
            last_headers: &[],
            last_block_utxo_root: None,
            // Default to EIP-50 / Sigma 6.0 activated (block-header version 4).
            // This is current mainnet reality and lets v6 MethodCall arms
            // dispatch in unit tests without per-test ceremony. Tests that
            // pin pre-JIT (< 2) or pre-EIP-50 (2) behavior hand-build the
            // context with the explicit version.
            activated_script_version: 3,
            // Default to a v6 ErgoTree (version 3) so v6 type-gated paths
            // (e.g. deserializeTo[SHeader]) work in unit tests without
            // per-test ceremony; tests pinning legacy behavior set it
            // explicitly.
            ergo_tree_version: 3,
        }
    }

    /// Whether the script under evaluation is a v6 (version >= 3) ErgoTree —
    /// Scala's `VersionContext.isV3OrLaterErgoTreeVersion`. Gates the v6 SHeader
    /// data-serialization paths.
    pub fn is_v3_ergo_tree(&self) -> bool {
        self.ergo_tree_version >= 3
    }

    /// Like [`minimal`], but activated at EIP-50 / Sigma 6.0 (block
    /// header version 4, `activatedScriptVersion = 3`). Used by tests
    /// that exercise v6 MethodCall arms; the activation gate in those
    /// arms rejects when `activated_script_version < 3`.
    pub fn minimal_v6(height: u32, self_creation_height: u32) -> Self {
        Self {
            activated_script_version: 3,
            ..Self::minimal(height, self_creation_height)
        }
    }

    /// Reject the current method invocation if `activated_script_version`
    /// is below `required`. Scala parity: every method-call goes through
    /// `MethodCall.evaluate`, which compares `method.methodVersion`
    /// (declared in `_v6Methods` etc.) against
    /// `context.activatedScriptVersion` and throws on mismatch. We
    /// surface this as a typed error so the validation layer can
    /// distinguish a *soft-fork* rejection from a generic script error.
    pub fn require_method_version(
        &self,
        type_id: u8,
        method_id: u8,
        required: u8,
    ) -> Result<(), EvalError> {
        if self.activated_script_version < required {
            Err(EvalError::SoftForkNotActivated {
                type_id,
                method_id,
                required,
                got: self.activated_script_version,
            })
        } else {
            Ok(())
        }
    }
}

/// Tag identifying which transaction-scoped box collection a `BoxRef`
/// points into. Carried alongside the index so `BoxRef { source, idx }`
/// can resolve to a real `EvalBox` against the active
/// [`ReductionContext`].
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BoxSource {
    /// Index resolves into [`ReductionContext::outputs`].
    Outputs,
    /// Index resolves into [`ReductionContext::inputs`].
    Inputs,
    /// Index resolves into [`ReductionContext::data_inputs`].
    DataInputs,
}

/// Runtime value produced during expression evaluation.
#[derive(Debug, Clone)]
pub enum Value {
    /// SUnit — the `()` literal. Zero serialization bytes.
    Unit,
    /// SByte — signed 8-bit integer. Produced by `Downcast[Byte]`,
    /// `SHeader.version`, `SPreHeader.version`, `SAvlTree.enabledOperations`,
    /// `ByIndex` on `Coll[Byte]`, and register lowering. Arithmetic uses
    /// `checked_*` and reports overflow as `EvalError::RuntimeException`
    /// (Scala `ByteIsExactIntegral` throws).
    Byte(i8),
    /// SShort — signed 16-bit integer. Same overflow-checked discipline as Byte.
    Short(i16),
    Int(i32),
    Long(i64),
    BigInt(num_bigint::BigInt),
    /// SUnsignedBigInt — Sigma 6.0 / v3 type. The wrapped `BigInt`
    /// must satisfy `0 <= n < 2^256`. The carrier type stays
    /// `num_bigint::BigInt` (not `BigUint`) so unsigned ↔ signed
    /// conversions (`toSigned`, `toUnsigned`) stay shape-compatible
    /// with the existing `Value::BigInt` arithmetic plumbing — only
    /// the semantic guarantees (non-negative, 256-bit upper bound,
    /// modular wrap on overflow) diverge.
    ///
    /// Distinct from `Value::BigInt` because Scala has separate
    /// `CBigInt` / `CUnsignedBigInt` runtime semantics
    /// (`core/.../sigma/data/CUnsignedBigInt.scala:13`): negative
    /// values can't reach this variant, and method dispatch like
    /// `multiplyMod`, `plusMod`, `modInverse` is only valid on this
    /// variant. Aliasing through `Value::BigInt` would silently
    /// accept negatives and miss the v6 method table.
    UnsignedBigInt(num_bigint::BigInt),
    Bool(bool),
    /// SString — UTF-8 string. Rare in scripts (mostly compile-time), but
    /// kept as a distinct carrier rather than lowered to `Coll[Byte]` so
    /// its type survives the value layer. This is load-bearing for
    /// `SGlobal.serialize`, whose Scala cost model charges SString (length
    /// via putUInt-no-info, 0 cost) strictly less than Coll[Byte] (length
    /// via putUShort, 3 cost); aliasing to `Coll[Byte]` would over-charge.
    Str(String),
    SigmaProp(SigmaBoolean),
    /// Real fixed-arity heterogeneous tuple from `STuple` types.
    /// Mutations like `Coll.updated`/`patch`/`slice` are rejected on
    /// this carrier — tuples are immutable in Scala-sigma.
    /// Constructed by `binding.rs` (`Tuple` opcode) and by
    /// `helpers.rs::sigma_to_value`'s `STuple` arm. NEVER use for
    /// "boxed-element Coll[X]"; use `CollGeneric` for that.
    Tuple(Vec<Value>),
    /// Boxed-element `Coll[X]` for non-primitive element types
    /// (Coll of tuple, Coll of Box-like via `CollBox`, etc.). The
    /// element variants inside `Vec<Value>` carry their own runtime
    /// shape, and the second field carries the static element
    /// `SigmaType` the IR's type system pinned at script-load time.
    /// Holding `elem_type` lets the carrier survive empty cases —
    /// without it, an empty `Coll[Tuple]` would be indistinguishable
    /// from an empty `Coll[Header]`, breaking `SGlobal.serialize`
    /// byte parity and the `Coll.updated` type-check.
    ///
    /// Read paths: emitted by `helpers::sigma_to_value` for
    /// `SColl(non-primitive)` constants and by every collection
    /// method that produces a boxed-element result (zip, reverse,
    /// distinct, flatMap, AVL batch entries).
    /// Write paths: accepted by `Coll.updated` (generic over the
    /// element type — check uses `elem_type` directly) and
    /// serialized back by `value_to_typed_sigma` (inverse of the
    /// `sigma_to_value` `SColl(non-primitive)` fallback).
    CollGeneric(Vec<Value>, Box<SigmaType>),
    CollBool(Vec<bool>),
    CollBytes(Vec<u8>),
    /// Token collection: Vec<(token_id_bytes, amount)> — opaque, only supports EQ
    Tokens(Vec<([u8; 32], u64)>),
    CollInt(Vec<i32>),
    CollLong(Vec<i64>),
    /// Typed `Coll[Short]` carrier. Previously `SColl(SShort)` fell through
    /// to `Value::Tuple`, losing element kind at runtime.
    CollShort(Vec<i16>),
    CollSigmaProp(Vec<SigmaBoolean>),
    /// Typed Coll[Box] — preserves element type even when empty.
    /// Elements are BoxRef or SelfBox values.
    CollBox(Vec<Value>),
    GroupElement([u8; 33]),
    Opt(Option<Box<Value>>),
    SelfBox,
    BoxRef {
        source: BoxSource,
        index: usize,
    },
    BoxCollection(BoxSource),
    /// SGlobal singleton — marker for Global method dispatch.
    Global,
    /// SPreHeader — carrier for PreHeader field access.
    PreHeader,
    /// Inline box constant — parsed from OpaqueBoxBytes in SBox constants.
    InlineBox(Box<EvalBox>),
    /// AvlTree constant — opaque data for register/constant storage.
    AvlTree(ergo_ser::sigma_value::AvlTreeData),
    /// SHeader — block header for CONTEXT.headers property access.
    Header(Box<EvalHeader>),
    /// `Coll[Header]` — typed collection of headers.
    CollHeader(Vec<EvalHeader>),
    /// Function closure — captured environment + parameter IDs/types + body.
    /// Not comparable (Ergo does not support function equality).
    /// Uses Rc for cheap cloning in collection operations.
    Func {
        captured_env: std::rc::Rc<Env>,
        params: Vec<u32>,
        /// Parameter types from FuncValue IR (used for type inference on empty maps).
        param_types: Vec<(u32, Option<SigmaType>)>,
        body: Box<Expr>,
    },
}

impl PartialEq for Value {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Value::Unit, Value::Unit) => true,
            (Value::Byte(a), Value::Byte(b)) => a == b,
            (Value::Short(a), Value::Short(b)) => a == b,
            (Value::Int(a), Value::Int(b)) => a == b,
            (Value::Long(a), Value::Long(b)) => a == b,
            (Value::BigInt(a), Value::BigInt(b)) => a == b,
            // `Value::UnsignedBigInt` is a *distinct* carrier from
            // `BigInt` (see `evaluator::types::Value` enum doc).
            // Omitting this arm makes every Scala-equivalent
            // `SUnsignedBigInt == SUnsignedBigInt` reduce to `false`
            // because the fall-through `_ => false` below catches it.
            // Real-world manifestation: testnet h=250,628 tx[1] input 0
            // — a v3 script that compares two `UnsignedBigInt` values
            // (computed via the EIP-50 modular-arithmetic methods) and
            // reduces to `TrivialProp(false)`, whose proof can never
            // verify.
            (Value::UnsignedBigInt(a), Value::UnsignedBigInt(b)) => a == b,
            (Value::Bool(a), Value::Bool(b)) => a == b,
            (Value::Str(a), Value::Str(b)) => a == b,
            (Value::CollShort(a), Value::CollShort(b)) => a == b,
            (Value::SigmaProp(a), Value::SigmaProp(b)) => a == b,
            (Value::Tuple(a), Value::Tuple(b)) => a == b,
            (Value::CollBool(a), Value::CollBool(b)) => a == b,
            (Value::CollBytes(a), Value::CollBytes(b)) => a == b,
            // Cross-type CollBytes == CollInt equality is intentionally
            // not handled here. Scala's DataValueComparer is type-strict;
            // a convenience arm here would mask missed byte-erasure
            // sites. With Value::Byte produced at Coll[Byte] element
            // boundaries, map/filter over Coll[Byte] stays as CollBytes
            // through the identity path, and any genuine cross-type
            // compare is a legitimate type error.
            (Value::Tokens(a), Value::Tokens(b)) => a == b,
            // Element-type field is intentionally NOT compared:
            // semantic equality is by elements, so two CollGenerics
            // tagged with structurally-different but elementwise-
            // compatible types (e.g. an empty `Coll[Tuple]` carrier
            // built two different ways) still compare equal when
            // their `items` match.
            (Value::CollGeneric(a, _), Value::CollGeneric(b, _)) => a == b,
            // Cross-representation: Tokens ↔ CollGeneric of (CollBytes, Long) pairs.
            // Slice/Filter/Map on Tokens produces CollGeneric of Tuple pairs via
            // values_to_collection, but SBox.tokens returns Value::Tokens.
            // Scala sees both as Coll[(Coll[Byte], Long)].
            (Value::Tokens(tokens), Value::CollGeneric(tuples, _))
            | (Value::CollGeneric(tuples, _), Value::Tokens(tokens)) => {
                tokens.len() == tuples.len()
                    && tokens.iter().zip(tuples.iter()).all(|((id, amt), t)| {
                        matches!(t, Value::Tuple(inner) if inner.len() == 2
                        && inner[0] == Value::CollBytes(id.to_vec())
                        && inner[1] == Value::Long(*amt as i64))
                    })
            }
            (Value::CollInt(a), Value::CollInt(b)) => a == b,
            (Value::CollLong(a), Value::CollLong(b)) => a == b,
            (Value::CollSigmaProp(a), Value::CollSigmaProp(b)) => a == b,
            (Value::CollBox(a), Value::CollBox(b)) => a == b,
            (Value::GroupElement(a), Value::GroupElement(b)) => a == b,
            (Value::Opt(a), Value::Opt(b)) => a == b,
            (Value::InlineBox(a), Value::InlineBox(b)) => a.id == b.id,
            (Value::AvlTree(a), Value::AvlTree(b)) => a == b,
            (Value::Header(a), Value::Header(b)) => a == b,
            (Value::CollHeader(a), Value::CollHeader(b)) => a == b,
            // Carrier types and functions: structural identity only
            (Value::SelfBox, Value::SelfBox) => true,
            (Value::Global, Value::Global) => true,
            (Value::PreHeader, Value::PreHeader) => true,
            (
                Value::BoxRef {
                    source: s1,
                    index: i1,
                },
                Value::BoxRef {
                    source: s2,
                    index: i2,
                },
            ) => s1 == s2 && i1 == i2,
            (Value::BoxCollection(a), Value::BoxCollection(b)) => a == b,
            // Func is never equal (Ergo has no function equality)
            (Value::Func { .. }, _) | (_, Value::Func { .. }) => false,
            // Different variants
            _ => false,
        }
    }
}

#[derive(Debug, Error)]
pub enum EvalError {
    #[error("unsupported opcode: 0x{0:02X}")]
    UnsupportedOpcode(u8),
    #[error("type error: expected {expected}, got {got}")]
    TypeError { expected: &'static str, got: String },
    #[error("constant index {0} out of bounds")]
    ConstantOutOfBounds(u32),
    #[error("unsupported constant type: {0:?}")]
    UnsupportedConstant(SigmaType),
    #[error("evaluation depth limit exceeded ({0})")]
    DepthLimitExceeded(usize),
    #[error("arity mismatch: function expects {expected} args, got {got}")]
    ArityMismatch { expected: usize, got: usize },
    #[error("cost limit exceeded: {0}")]
    CostExceeded(String),
    /// `JitCost` arithmetic overflowed the Scala `Int.MaxValue` bound
    /// (see `ergo_primitives::cost::SCALA_INT_MAX`). Held typed so the
    /// validation boundary can route it to
    /// `ValidationError::JitCostOverflow` rather than collapsing it into
    /// a generic script error.
    #[error("JitCost arithmetic overflow: {0}")]
    JitCostOverflow(JitCostError),
    /// Opcode is registered in Scala's serializer for round-trip parity but
    /// has no executable path (e.g., `BitInversion` at `trees.scala:906`).
    #[error("opcode 0x{0:02X} ({1}) is not executable in the reference interpreter")]
    NotExecutable(u8, &'static str),
    /// Opcode is deprecated; serializer exists for deserialization parity only
    /// (e.g., `ModQ` family at `ValueSerializer.scala:138-144`).
    #[error("opcode 0x{0:02X} is deprecated and serializer-only")]
    DeprecatedOpcode(u8),
    /// Opcode is internal to the reducer pipeline and must not appear in
    /// user-level ErgoTree (e.g., `SigmaPropIsProven`).
    #[error("opcode 0x{0:02X} ({1}) is internal and must not appear in user trees")]
    InternalOpcode(u8, &'static str),
    /// Runtime pre-condition failed inside an opcode (shift out of range,
    /// byte-array length mismatch, arithmetic overflow on Byte/Short, …).
    /// Mirrors Scala's `ArithmeticException` / `IllegalArgumentException`
    /// raised inside `ExactIntegral` / `BigIntegerOps`.
    #[error("runtime exception: {0}")]
    RuntimeException(&'static str),
    /// `ctx.last_headers` was empty when an opcode (e.g., `LastBlockUtxoRootHash`)
    /// required the parent header. Indicates a context-construction invariant
    /// was violated upstream — the caller is responsible for populating the
    /// header window before invoking opcodes that depend on it.
    #[error("header window is empty; LastBlockUtxoRootHash unavailable")]
    EmptyHeaderWindow,
    /// A soft-fork-gated method was invoked at an `activatedScriptVersion`
    /// below its activation threshold. EIP-50 / Sigma 6.0 methods
    /// require `activatedScriptVersion >= 3` (block-header version 4).
    /// Scala parity: `MethodCall.evaluate` checks `method.methodVersion
    /// <= activatedScriptVersion` and throws `InterpreterException`
    /// otherwise; we surface it as a typed error so the validation
    /// boundary can route soft-fork rejections distinctly from generic
    /// script errors.
    #[error(
        "MethodCall ({type_id}, {method_id}) requires activatedScriptVersion >= {required}, got {got}"
    )]
    SoftForkNotActivated {
        type_id: u8,
        method_id: u8,
        required: u8,
        got: u8,
    },
}

// `?` propagation for the cost API. Both impls preserve the typed
// JitCost overflow as `EvalError::JitCostOverflow` so the validation
// boundary can route it to `ValidationError::JitCostOverflow` instead
// of collapsing it into a generic script error.
impl From<JitCostError> for EvalError {
    fn from(e: JitCostError) -> Self {
        EvalError::JitCostOverflow(e)
    }
}

impl From<CostError> for EvalError {
    fn from(e: CostError) -> Self {
        match e {
            CostError::LimitExceeded { current, limit } => {
                EvalError::CostExceeded(format!("{current} > {limit} (JitCost units)"))
            }
            CostError::Overflow(je) => EvalError::JitCostOverflow(je),
        }
    }
}

/// Runtime evaluation-depth backstop. Set to the PARSER bound
/// (`ergo_ser` `MAX_EXPR_DEPTH` = Scala `SigmaConstants.MaxTreeDepth` = 110),
/// NOT below it: a tree that successfully parsed is at most 110 levels deep, so
/// this guard never fires for a parser-accepted tree — it only backstops
/// AST-constructed or deserialize-extended inputs against stack overflow. A
/// lower value would reject trees the parser (= Scala, which has no runtime
/// eval-depth limit, only cost) accepts → reject-valid. Scala's deserialize-time
/// `DeserializeCallDepthExceeded` (also 110) is the analog; keep the guard.
pub(crate) const MAX_EVAL_DEPTH: usize = 110;

/// Variable environment for let-bindings (ValDef/ValUse).
pub(crate) type Env = std::collections::HashMap<u32, Value>;
