//! Ergo box wire codecs.
//!
//! Split by direction and mode:
//!
//! * `mod.rs` — the [`ErgoBoxCandidate`] / [`ErgoBox`] data types
//!   (including the validating `try_from_raw_parts` constructor) and the
//!   shared `check_token_count` wire-cap helper.
//! * `candidate.rs` — standalone-mode candidate codec (full token IDs).
//! * `candidate_indexed.rs` — transaction-mode candidate codec (token IDs
//!   as indexes into the enclosing transaction's token table).
//! * `whole.rs` — whole-`ErgoBox` codec, `box_id` helpers, and the
//!   vector-assisted `parse_ergo_box_bytes`.

use ergo_primitives::digest::{blake2b256, Digest32, ModifierId};
use ergo_primitives::reader::VlqReader;
use ergo_primitives::writer::VlqWriter;

use crate::ergo_tree::{read_ergo_tree, write_ergo_tree, ErgoTree};
use crate::error::WriteError;
use crate::register::{read_registers, write_registers, AdditionalRegisters};
use crate::token::Token;

mod candidate;
mod candidate_indexed;
mod whole;

pub use candidate::{
    read_accepted_ergo_box_candidate, read_ergo_box_candidate, write_ergo_box_candidate,
    write_ergo_box_candidate_versioned,
};
pub(crate) use candidate_indexed::write_ergo_box_candidate_indexed_for_wire_check;
pub use candidate_indexed::{read_ergo_box_candidate_indexed, write_ergo_box_candidate_indexed};
pub use whole::{
    box_id_with, parse_ergo_box_bytes, read_accepted_ergo_box, read_ergo_box, serialize_ergo_box,
    write_ergo_box,
};

/// Parsed box candidate with a structured ErgoTree.
///
/// The ErgoTree is stored in parsed form AND as the bytes it was read from
/// ([`ErgoBoxCandidate::ergo_tree_bytes`], Scala's `propositionBytes`). The box
/// is written with the canonical re-serialization of the parsed tree
/// ([`ErgoBoxCandidate::serialized_ergo_tree_bytes`]), which is the same bytes
/// for every canonically encoded tree.
///
/// # Parsing and retained bytes
///
/// Standalone and transaction readers locate non-size-delimited tree boundaries
/// by parsing the opcode expression. Size-delimited trees also support Scala's
/// opaque soft-fork representation. [`parse_ergo_box_bytes`] additionally checks
/// that supplied proposition bytes agree with the bytes in the complete box.
///
/// Received proposition bytes and canonical serialization can differ; use the
/// documented accessors for the required identity rather than treating them as
/// interchangeable. Registers retain the evaluated-value forms needed for
/// canonical box serialization.
#[derive(Debug, Clone)]
pub struct ErgoBoxCandidate {
    /// Box value in nanoErg.
    pub value: u64,
    ergo_tree: ErgoTree,
    ergo_tree_bytes: Vec<u8>,
    /// The canonical re-serialization of `ergo_tree`, kept only when it differs
    /// from `ergo_tree_bytes`. See [`ErgoBoxCandidate::serialized_ergo_tree_bytes`].
    canonical_tree_bytes: Result<Option<Vec<u8>>, WriteError>,
    /// Block height at which this candidate is created (consensus
    /// rejects boxes whose `creation_height` is greater than the
    /// containing block's height).
    pub creation_height: u32,
    /// Tokens carried by the box, in their on-wire order.
    pub tokens: Vec<Token>,
    /// Non-mandatory registers R4-R9 (densely packed from R4 upward).
    additional_registers: AdditionalRegisters,
    register_bytes: Vec<u8>,
    // A parsed whole box can retain received bytes even when its registers
    // cannot be written. Cache the failure rather than rejecting read-only use.
    register_serialization_error: Option<WriteError>,
    // Standalone box serializers use the ambient parse version; newly sealed
    // transaction outputs serialize under Scala's default VersionContext(1,1).
    // Indexed transaction serialization keeps register_bytes independently.
    box_serialization_version: u8,
    // Present only for a parsed whole box whose received identity differs from
    // canonical serialization. Include it in equality: identity-distinct
    // received candidates must not alias in equality-keyed caller caches.
    received_box_identity: Option<Box<ReceivedBoxIdentity>>,
}

// Equal candidates must also encode equal whole-box register bytes.
// Version provenance is ignored only when it has no effect on that encoding.
impl PartialEq for ErgoBoxCandidate {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
            && self.ergo_tree == other.ergo_tree
            && self.ergo_tree_bytes == other.ergo_tree_bytes
            && self.canonical_tree_bytes == other.canonical_tree_bytes
            && self.creation_height == other.creation_height
            && self.tokens == other.tokens
            && self.additional_registers == other.additional_registers
            && self.register_bytes == other.register_bytes
            && self.register_serialization_error == other.register_serialization_error
            && self.received_box_identity == other.received_box_identity
            && (self.box_serialization_version == other.box_serialization_version || {
                let encode = |version| {
                    let mut w = VlqWriter::new();
                    crate::register::write_registers_versioned(
                        &mut w,
                        &self.additional_registers,
                        version,
                    )
                    .ok()
                    .map(|()| w.result())
                };
                encode(self.box_serialization_version) == encode(other.box_serialization_version)
            })
    }
}

/// The received identity of a parsed whole box whose encoding differs from its
/// canonical serialization. The box ID hashes these received bytes while the
/// box's value, creation height, tokens, transaction ID and index still equal
/// the values recorded here; see [`ErgoBox::box_id`]. Read-only: obtained from
/// [`ErgoBoxCandidate::received_box_identity`].
#[derive(Debug, Clone, PartialEq)]
pub struct ReceivedBoxIdentity {
    id: Digest32,
    bytes: Vec<u8>,
    value: u64,
    creation_height: u32,
    tokens: Vec<Token>,
    transaction_id: ModifierId,
    index: u16,
}

impl ReceivedBoxIdentity {
    /// `blake2b256` of the received whole-box bytes.
    pub fn id(&self) -> Digest32 {
        self.id
    }

    /// The received whole-box bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Box value recorded when the bytes were received.
    pub fn value(&self) -> u64 {
        self.value
    }

    /// Creation height recorded when the bytes were received.
    pub fn creation_height(&self) -> u32 {
        self.creation_height
    }

    /// Tokens recorded when the bytes were received.
    pub fn tokens(&self) -> &[Token] {
        &self.tokens
    }

    /// Minting transaction ID recorded when the bytes were received.
    pub fn transaction_id(&self) -> ModifierId {
        self.transaction_id
    }

    /// Output index recorded when the bytes were received.
    pub fn index(&self) -> u16 {
        self.index
    }
}

impl ErgoBoxCandidate {
    /// Build from an ErgoTree struct, serializing it to raw bytes.
    pub fn new(
        value: u64,
        ergo_tree: ErgoTree,
        creation_height: u32,
        tokens: Vec<Token>,
        additional_registers: AdditionalRegisters,
    ) -> Result<Self, WriteError> {
        let mut w = VlqWriter::new();
        write_ergo_tree(&mut w, &ergo_tree)?;
        let ergo_tree_bytes = w.result();
        let mut rw = VlqWriter::new();
        write_registers(&mut rw, &additional_registers)?;
        let register_bytes = rw.result();
        Ok(Self {
            value,
            ergo_tree,
            ergo_tree_bytes,
            canonical_tree_bytes: Ok(None),
            creation_height,
            tokens,
            additional_registers,
            register_bytes,
            register_serialization_error: None,
            box_serialization_version: 1,
            received_box_identity: None,
        })
    }

    /// Build from already-trusted canonical parts without reserialization.
    /// Reference acceptance alone does not establish canonicality: accepted
    /// bytes can normalize when written. Use the checked constructor when that
    /// distinction has not already been established. Parsed whole-box received
    /// identity belongs to the whole-box reader, not this candidate constructor.
    ///
    /// # Safety contract
    ///
    /// Caller MUST guarantee:
    /// - `ergo_tree_bytes` is the canonical serialization of `ergo_tree`
    /// - `register_bytes` is the canonical serialization of
    ///   `additional_registers`
    ///
    /// No runtime check is performed. A mismatch silently produces a
    /// candidate whose serialized bytes disagree with its parsed
    /// fields, desyncing `box_id` from inspection. Prefer
    /// [`ErgoBoxCandidate::try_from_raw_parts`] when the caller cannot
    /// guarantee the contract, or [`ErgoBoxCandidate::new`] when no
    /// external byte fixture is being preserved.
    pub fn from_trusted_raw_parts(
        value: u64,
        ergo_tree: ErgoTree,
        ergo_tree_bytes: Vec<u8>,
        creation_height: u32,
        tokens: Vec<Token>,
        additional_registers: AdditionalRegisters,
        register_bytes: Vec<u8>,
    ) -> Self {
        Self {
            value,
            ergo_tree,
            ergo_tree_bytes,
            canonical_tree_bytes: Ok(None),
            creation_height,
            tokens,
            additional_registers,
            register_bytes,
            register_serialization_error: None,
            box_serialization_version: 3,
            received_box_identity: None,
        }
    }

    /// Validating counterpart to [`ErgoBoxCandidate::from_trusted_raw_parts`].
    ///
    /// Re-parses `ergo_tree_bytes` and `register_bytes` and checks the
    /// result equals the supplied `ergo_tree` / `additional_registers`.
    /// Returns `WriteError::InvalidData` on any mismatch — including
    /// re-parse failure, trailing bytes after parse, or a parse
    /// success that does not equal the supplied parsed value. On
    /// success the candidate retains the received tree bytes for
    /// `propositionBytes`, while writers use canonical tree and register
    /// serialization. Sealing this candidate creates a new canonical box;
    /// use a whole-box reader to retain a received whole box's cached ID.
    ///
    /// Cost: one re-parse and canonical serialization of the tree and registers
    /// per call. Prefer this constructor when the invariant is not guaranteed;
    /// the unchecked [`ErgoBoxCandidate::from_trusted_raw_parts`] requires
    /// canonical bytes. Internal readers produce the parsed and cached fields
    /// atomically from the same reader.
    pub fn try_from_raw_parts(
        value: u64,
        ergo_tree: ErgoTree,
        ergo_tree_bytes: Vec<u8>,
        creation_height: u32,
        tokens: Vec<Token>,
        additional_registers: AdditionalRegisters,
        register_bytes: Vec<u8>,
    ) -> Result<Self, WriteError> {
        let mut tr = VlqReader::new(&ergo_tree_bytes);
        let parsed_tree = read_ergo_tree(&mut tr)
            .map_err(|e| WriteError::InvalidData(format!("ergo_tree_bytes do not parse: {e}")))?;
        // `tr` / `rr` below are fresh, never-scoped readers: this constructor
        // has no `VersionContext` of its own (it is not a consensus parse — its
        // callers hand it already-parsed values), so it runs under Scala's
        // default context, activated 1, spelled out rather than looked up.
        crate::ergo_tree::check_tree_version_supported(
            &parsed_tree,
            crate::ergo_tree::DEFAULT_ACTIVATED_SCRIPT_VERSION,
        )
        .map_err(|e| {
            WriteError::InvalidData(format!("ergo_tree_bytes have an unsupported version: {e}"))
        })?;
        crate::ergo_tree::check_header_size_bit(&parsed_tree).map_err(|e| {
            WriteError::InvalidData(format!("ergo_tree_bytes fail CheckHeaderSizeBit: {e}"))
        })?;
        crate::ergo_tree::check_resolvable_methods(&parsed_tree).map_err(|e| {
            WriteError::InvalidData(format!(
                "ergo_tree_bytes carry a method the tree's registry cannot resolve: {e}"
            ))
        })?;
        crate::ergo_tree::check_sigma_prop_root(&parsed_tree).map_err(|e| {
            WriteError::InvalidData(format!("ergo_tree_bytes have a non-SigmaProp root: {e}"))
        })?;
        if !tr.is_empty() {
            return Err(WriteError::InvalidData(
                "ergo_tree_bytes have trailing content after parse".into(),
            ));
        }
        if parsed_tree != ergo_tree {
            return Err(WriteError::InvalidData(
                "ergo_tree_bytes parse to a different tree than the supplied parsed value".into(),
            ));
        }

        let mut rr = VlqReader::new(&register_bytes);
        let parsed_registers = read_registers(&mut rr)
            .map_err(|e| WriteError::InvalidData(format!("register_bytes do not parse: {e}")))?;
        if !rr.is_empty() {
            return Err(WriteError::InvalidData(
                "register_bytes have trailing content after parse".into(),
            ));
        }
        if parsed_registers != additional_registers {
            return Err(WriteError::InvalidData(
                "register_bytes parse to different registers than the supplied parsed value".into(),
            ));
        }

        let canonical_tree_bytes = canonical_tree_bytes(&ergo_tree, &ergo_tree_bytes);
        let mut writer = VlqWriter::new();
        write_registers(&mut writer, &additional_registers)?;
        let register_bytes = writer.result();
        Ok(Self {
            value,
            ergo_tree,
            ergo_tree_bytes,
            canonical_tree_bytes,
            creation_height,
            tokens,
            additional_registers,
            register_bytes,
            register_serialization_error: None,
            box_serialization_version: 3,
            received_box_identity: None,
        })
    }

    /// Borrow the parsed `ErgoTree` carried by this candidate.
    pub fn ergo_tree(&self) -> &ErgoTree {
        &self.ergo_tree
    }

    /// The `ErgoTree` bytes as received: Scala's `ErgoTree.bytes`, which is
    /// what a script reads as `propositionBytes` and what the proposition-size
    /// and storage-rent checks compare. For a tree parsed off the wire these
    /// are the exact input bytes, even where they are not canonical.
    pub fn ergo_tree_bytes(&self) -> &[u8] {
        &self.ergo_tree_bytes
    }

    /// The `ErgoTree` bytes emitted by the candidate writers. Newly sealed
    /// boxes and transaction serialization commit to these bytes. An unchanged
    /// parsed whole box can retain a different received ID; see [`ErgoBox::box_id`].
    ///
    /// Scala writes a box's tree back from the parsed structure
    /// (`ErgoBoxCandidate.serializeBodyWithIndexedDigests` calls
    /// `DefaultSerializer.serializeErgoTree`, `ErgoBoxCandidate.scala:142`),
    /// never from the bytes it read. So a tree the reference accepts in a
    /// non-canonical form (a declared size that is not the body's length, a
    /// constants count that wraps negative, a `TrueLeaf` opcode, an over-long
    /// VLQ) is written back canonically, while `propositionBytes` keeps the
    /// input. A soft-fork-wrapped tree is written back as it was read.
    pub fn serialized_ergo_tree_bytes(&self) -> &[u8] {
        self.canonical_tree_bytes
            .as_ref()
            .ok()
            .and_then(|bytes| bytes.as_deref())
            .unwrap_or(&self.ergo_tree_bytes)
    }

    /// Validate structured scripts before falling back to uncached wire bytes.
    /// Scala propagates script serialization failures when writing a box.
    pub fn checked_serialized_ergo_tree_bytes(&self) -> Result<&[u8], WriteError> {
        self.canonical_tree_bytes.as_ref().map_err(Clone::clone)?;
        Ok(self.serialized_ergo_tree_bytes())
    }

    /// Non-mandatory registers R4-R9, kept consistent with [`Self::register_bytes`].
    /// Use [`Self::replace_additional_registers`] to change the register block.
    pub fn additional_registers(&self) -> &AdditionalRegisters {
        &self.additional_registers
    }

    /// Replace the register block and its cached serialization atomically.
    ///
    /// The new values must serialize and parse as valid box registers. If
    /// validation fails, both the parsed values and wire bytes stay unchanged.
    pub fn replace_additional_registers(
        &mut self,
        registers: AdditionalRegisters,
    ) -> Result<(), WriteError> {
        let mut writer = VlqWriter::new();
        write_registers(&mut writer, &registers)?;
        let bytes = writer.result();
        let mut reader = VlqReader::new(&bytes);
        let parsed = read_registers(&mut reader).map_err(|error| {
            WriteError::InvalidData(format!("invalid replacement registers: {error}"))
        })?;
        if !reader.is_empty() || parsed != registers {
            return Err(WriteError::InvalidData(
                "replacement registers do not round-trip through the box register codec".into(),
            ));
        }
        self.additional_registers = registers;
        self.register_bytes = bytes;
        self.register_serialization_error = None;
        self.received_box_identity = None;
        Ok(())
    }

    /// The serialized `additional_registers`: the `count(u8) ||
    /// concat(register_bytes)` wire form, feed it to `split_register_bytes` to
    /// recover per-register hex. A parsed box keeps the CANONICAL
    /// re-serialization of its registers, as Scala writes a box back from its
    /// parsed register values. If serialization failed, the received register
    /// slice remains available for read-only consumers; writers return the
    /// cached error through [`Self::checked_register_bytes`].
    pub fn register_bytes(&self) -> &[u8] {
        &self.register_bytes
    }

    /// Script version this candidate's registers serialize under in whole-box
    /// bytes. A parsed candidate takes its reader's activated script version
    /// (3 when unset); [`ErgoBoxCandidate::new`] and [`ErgoBox::new`] use 1.
    pub fn box_serialization_version(&self) -> u8 {
        self.box_serialization_version
    }

    /// The received identity of a parsed whole box whose encoding differs from
    /// canonical serialization; `None` for canonical, built or changed boxes.
    pub fn received_box_identity(&self) -> Option<&ReceivedBoxIdentity> {
        self.received_box_identity.as_deref()
    }

    /// Cached structured register bytes, or the original serialization failure.
    pub fn checked_register_bytes(&self) -> Result<&[u8], WriteError> {
        match &self.register_serialization_error {
            Some(error) => Err(error.clone()),
            None => Ok(&self.register_bytes),
        }
    }
}

/// A confirmed ergo box: an [`ErgoBoxCandidate`] plus the identity of
/// the transaction that minted it and the output index within that
/// transaction. The pair `(transaction_id, index)` is what `box_id` is
/// derived from when the candidate is sealed into a block.
#[derive(Debug, Clone, PartialEq)]
pub struct ErgoBox {
    /// The output candidate as defined in the minting transaction.
    pub candidate: ErgoBoxCandidate,
    /// Identifier of the transaction that produced this box.
    pub transaction_id: ModifierId,
    /// Output index of this box within `transaction_id`.
    pub index: u16,
}

impl ErgoBox {
    /// Seal a candidate as a new box, using its canonical serialization for ID.
    /// This clears received whole-box identity even when resealing a clone with
    /// the same transaction ID and index, matching Scala's new-box constructor.
    pub fn new(mut candidate: ErgoBoxCandidate, transaction_id: ModifierId, index: u16) -> Self {
        candidate.received_box_identity = None;
        candidate.box_serialization_version = 1;
        Self {
            candidate,
            transaction_id,
            index,
        }
    }

    /// The box's ID. An unchanged parsed whole box hashes its received bytes,
    /// matching Scala's cached `ErgoBox.bytes`; a newly sealed or changed box
    /// hashes canonical serialization. These identities can differ for accepted
    /// non-canonical encodings. Use [`Self::new`] when sealing a candidate.
    pub fn box_id(&self) -> Result<Digest32, WriteError> {
        if let Some(id) = self.received_box_id() {
            return Ok(id);
        }
        let bytes = serialize_ergo_box(self)?;
        Ok(blake2b256(&bytes))
    }

    /// Scala ErgoBox.bytes retains received bytes for an unchanged parsed box.
    /// Structured serializers remain separate, and can normalize or fail.
    /// <https://github.com/ergoplatform/sigmastate-interpreter/blob/v6.0.7/data/shared/src/main/scala/org/ergoplatform/ErgoBox.scala#L87-L92>
    pub fn bytes(&self) -> Result<Vec<u8>, WriteError> {
        if self.received_box_id().is_some() {
            return Ok(self
                .candidate
                .received_box_identity
                .as_ref()
                .unwrap()
                .bytes
                .clone());
        }
        serialize_ergo_box(self)
    }

    fn received_box_id(&self) -> Option<Digest32> {
        let original = self.candidate.received_box_identity.as_ref()?;
        (self.candidate.value == original.value
            && self.candidate.creation_height == original.creation_height
            && self.candidate.tokens == original.tokens
            && self.transaction_id == original.transaction_id
            && self.index == original.index)
            .then_some(original.id)
    }

    fn remember_received_bytes(&mut self, bytes: &[u8]) {
        // Canonical boxes need no metadata; their existing structural equality
        // and cheap candidate representation remain unchanged. Equal bytes have
        // equal IDs, so only a differing encoding is hashed.
        if serialize_ergo_box(self).is_ok_and(|canonical| canonical == bytes) {
            return;
        }
        self.candidate.received_box_identity = Some(Box::new(ReceivedBoxIdentity {
            id: blake2b256(bytes),
            bytes: bytes.to_vec(),
            value: self.candidate.value,
            creation_height: self.candidate.creation_height,
            tokens: self.candidate.tokens.clone(),
            transaction_id: self.transaction_id,
            index: self.index,
        }));
    }
}

/// The canonical re-serialization of a parsed tree, when it differs from the
/// bytes it was read from; see [`ErgoBoxCandidate::serialized_ergo_tree_bytes`].
/// Cache write failures as well, so later serializers cannot fall back to input.
pub(crate) fn canonical_tree_bytes(
    tree: &ErgoTree,
    input: &[u8],
) -> Result<Option<Vec<u8>>, WriteError> {
    // Scala writes UnparsedErgoTree bytes verbatim, including its discarded
    // constants. Preserve those bytes without asking the standalone writer to
    // re-establish the opaque body's boundary.
    // https://github.com/ergoplatform/sigmastate-interpreter/blob/v6.0.7/data/shared/src/main/scala/sigma/serialization/ErgoTreeSerializer.scala#L105-L128
    if matches!(tree.body, crate::opcode::Expr::Unparsed(_)) {
        return Ok(None);
    }
    let mut w = VlqWriter::new();
    write_ergo_tree(&mut w, tree)?;
    let canonical = w.result();
    Ok((canonical != input).then_some(canonical))
}

/// `SigmaConstants.MaxBoxSize`: `ErgoBoxCandidate.parseBodyWithIndexedDigests`
/// bounds a candidate's body (value .. registers) to a window of this many
/// bytes from its start (ErgoBoxCandidate.scala:190-191). A read that begins
/// past it is rule 1014, which no box read catches: the box is rejected.
pub(crate) const MAX_BOX_SIZE: usize = 4096;

/// Scala writes the per-box token count as a single unsigned byte;
/// >255 tokens would silently wrap on `as u8` and corrupt the wire form.
fn check_token_count(len: usize) -> Result<(), WriteError> {
    if len > u8::MAX as usize {
        return Err(WriteError::InvalidData(format!(
            "ErgoBox token count too large for Scala wire format: {len} (max 255)"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::opcode::Expr;
    use crate::sigma_type::SigmaType;
    use crate::sigma_value::SigmaValue;

    // ----- helpers -----

    fn size_delimited_tree() -> ErgoTree {
        ErgoTree {
            version: 0,
            has_size: true,
            constant_segregation: false,
            reserved_header_bits: 0,
            constants: vec![],
            // Root must be SSigmaProp: under `has_size`, a non-SigmaProp root
            // (e.g. `Const(SBoolean, true)`) fails Scala's
            // CheckDeserializedScriptIsSigmaProp and is soft-fork-wrapped into
            // `Expr::Unparsed` on re-parse, so it would not survive a
            // round-trip as a parsed body.
            body: Expr::Const {
                tpe: SigmaType::SSigmaProp,
                val: SigmaValue::SigmaProp(crate::sigma_value::SigmaBoolean::TrivialProp(true)),
            },
        }
    }

    // ----- read-only accessors -----

    fn sealed_box() -> ErgoBox {
        let candidate = ErgoBoxCandidate::new(
            1,
            size_delimited_tree(),
            7,
            vec![],
            AdditionalRegisters::empty(),
        )
        .unwrap();
        ErgoBox::new(candidate, ModifierId::from_bytes([0x5A; 32]), 2)
    }

    #[test]
    fn accessors_report_built_and_sealed_candidates() {
        let candidate = ErgoBoxCandidate::new(
            1,
            size_delimited_tree(),
            7,
            vec![],
            AdditionalRegisters::empty(),
        )
        .unwrap();
        assert_eq!(candidate.box_serialization_version(), 1);
        assert!(candidate.received_box_identity().is_none());
        let sealed = sealed_box();
        assert_eq!(sealed.candidate.box_serialization_version(), 1);
        assert!(sealed.candidate.received_box_identity().is_none());
    }

    #[test]
    fn accessors_report_parsed_candidate_version_and_canonical_identity() {
        let sealed = sealed_box();
        let bytes = serialize_ergo_box(&sealed).unwrap();
        let mut r = VlqReader::new(&bytes).with_activated_script_version(2);
        let parsed = read_ergo_box(&mut r).unwrap();
        assert_eq!(parsed.candidate.box_serialization_version(), 2);
        // Canonical received bytes record no separate identity.
        assert!(parsed.candidate.received_box_identity().is_none());
    }

    #[test]
    fn received_box_identity_accessors_expose_the_non_canonical_encoding() {
        let sealed = sealed_box();
        let canonical = serialize_ergo_box(&sealed).unwrap();
        // Value 1 is the leading VLQ byte; encode it non-minimally as 81 00.
        assert_eq!(canonical[0], 0x01);
        let mut received = vec![0x81, 0x00];
        received.extend_from_slice(&canonical[1..]);
        let parsed = read_ergo_box(&mut VlqReader::new(&received)).unwrap();
        let identity = parsed.candidate.received_box_identity().unwrap();
        assert_eq!(identity.id(), blake2b256(&received));
        assert_eq!(identity.bytes(), received.as_slice());
        assert_eq!(identity.value(), 1);
        assert_eq!(identity.creation_height(), 7);
        assert!(identity.tokens().is_empty());
        assert_eq!(
            identity.transaction_id(),
            ModifierId::from_bytes([0x5A; 32])
        );
        assert_eq!(identity.index(), 2);
        assert_eq!(parsed.box_id().unwrap(), identity.id());
    }

    // ----- atomic register replacement -----

    #[test]
    fn replace_additional_registers_matches_external_scala_bytes_and_box_ids() {
        let oracle: serde_json::Value = serde_json::from_str(include_str!(
            "../../../test-vectors/scala/evaluated_value_forms.json"
        ))
        .unwrap();
        let prefix = oracle["box_prefix"]["candidate_prefix_hex"]
            .as_str()
            .unwrap();
        for form in oracle["forms"].as_array().unwrap() {
            let Some(expected_id) = form["box_id"].as_str().filter(|id| id.len() == 64) else {
                continue;
            };
            let canonical = form["register_reserialized_hex"]
                .as_str()
                .or_else(|| form["scala_reserialized_value_hex"].as_str())
                .unwrap();
            let bytes = hex::decode(format!(
                "{prefix}{}",
                form["register_hex"].as_str().unwrap()
            ))
            .unwrap();
            let parsed = read_ergo_box_candidate(&mut VlqReader::new(&bytes)).unwrap();
            let mut candidate = ErgoBoxCandidate::new(
                parsed.value,
                parsed.ergo_tree().clone(),
                parsed.creation_height,
                parsed.tokens.clone(),
                AdditionalRegisters::empty(),
            )
            .unwrap();
            candidate
                .replace_additional_registers(parsed.additional_registers().clone())
                .unwrap();
            assert_eq!(
                candidate.additional_registers(),
                parsed.additional_registers()
            );
            assert_eq!(
                hex::encode(candidate.register_bytes()),
                format!("01{canonical}")
            );
            let ergo_box = ErgoBox {
                candidate,
                transaction_id: ModifierId::from_bytes([7; 32]),
                index: 3,
            };
            assert_eq!(
                hex::encode(ergo_box.box_id().unwrap().as_bytes()),
                expected_id,
                "{}",
                form["name"]
            );
            let serialized = serialize_ergo_box(&ergo_box).unwrap();
            let reparsed = read_ergo_box(&mut VlqReader::new(&serialized)).unwrap();
            assert_eq!(reparsed, ergo_box);
        }
    }

    #[test]
    fn replace_additional_registers_invalid_value_leaves_candidate_unchanged() {
        use crate::register::RegisterValue;
        let original = ErgoBoxCandidate::new(
            1_000_000,
            size_delimited_tree(),
            100,
            vec![],
            AdditionalRegisters {
                registers: vec![RegisterValue {
                    tpe: SigmaType::SInt,
                    value: SigmaValue::Int(7),
                }],
            },
        )
        .unwrap();
        let invalid = [
            AdditionalRegisters {
                registers: vec![
                    RegisterValue {
                        tpe: SigmaType::SInt,
                        value: SigmaValue::Int(1),
                    };
                    7
                ],
            },
            AdditionalRegisters {
                registers: vec![RegisterValue {
                    tpe: SigmaType::SInt,
                    value: SigmaValue::Boolean(true),
                }],
            },
            // The writer accepts an Option constant, but Scala's box-register
            // reader forbids v6-only types. Validation must also be atomic.
            AdditionalRegisters {
                registers: vec![RegisterValue {
                    tpe: SigmaType::SOption(Box::new(SigmaType::SInt)),
                    value: SigmaValue::Opt(None),
                }],
            },
        ];
        for registers in invalid {
            let mut candidate = original.clone();
            assert!(candidate.replace_additional_registers(registers).is_err());
            assert_eq!(candidate, original);
            let mut before = VlqWriter::new();
            let mut after = VlqWriter::new();
            write_ergo_box_candidate(&mut before, &original).unwrap();
            write_ergo_box_candidate(&mut after, &candidate).unwrap();
            assert_eq!(after.result(), before.result());
        }
    }

    // ----- ErgoBoxCandidate::try_from_raw_parts validation -----

    #[test]
    fn try_from_raw_parts_accepts_matching_bytes() {
        let tree = size_delimited_tree();
        let mut tw = VlqWriter::new();
        crate::ergo_tree::write_ergo_tree(&mut tw, &tree).unwrap();
        let tree_bytes = tw.result();

        let regs = AdditionalRegisters::empty();
        let mut rw = VlqWriter::new();
        write_registers(&mut rw, &regs).unwrap();
        let reg_bytes = rw.result();

        let cand = ErgoBoxCandidate::try_from_raw_parts(
            1_000_000,
            tree.clone(),
            tree_bytes.clone(),
            100,
            vec![],
            regs.clone(),
            reg_bytes.clone(),
        )
        .expect("matching bytes/parsed must succeed");

        // Bytes preserved verbatim.
        assert_eq!(cand.ergo_tree_bytes(), &tree_bytes[..]);
        assert_eq!(cand.register_bytes(), &reg_bytes[..]);
    }

    #[test]
    fn try_from_raw_parts_rejects_garbage_tree_bytes() {
        let tree = size_delimited_tree();
        let regs = AdditionalRegisters::empty();
        let mut rw = VlqWriter::new();
        write_registers(&mut rw, &regs).unwrap();
        let reg_bytes = rw.result();

        let err = ErgoBoxCandidate::try_from_raw_parts(
            1_000_000,
            tree,
            vec![0xFF, 0xFF, 0xFF],
            100,
            vec![],
            regs,
            reg_bytes,
        )
        .unwrap_err();
        let WriteError::InvalidData(msg) = &err;
        assert!(
            msg.contains("ergo_tree_bytes"),
            "msg should name field, got: {msg}"
        );
    }

    #[test]
    fn try_from_raw_parts_rejects_mismatched_tree() {
        // Build bytes for one tree, supply a different parsed tree.
        let tree_a = size_delimited_tree();
        let tree_b = ErgoTree {
            version: 0,
            has_size: true,
            constant_segregation: false,
            reserved_header_bits: 0,
            constants: vec![],
            body: Expr::Const {
                tpe: SigmaType::SBoolean,
                val: SigmaValue::Boolean(false),
            },
        };
        assert_ne!(tree_a, tree_b);

        let mut tw = VlqWriter::new();
        crate::ergo_tree::write_ergo_tree(&mut tw, &tree_a).unwrap();
        let tree_a_bytes = tw.result();

        let regs = AdditionalRegisters::empty();
        let mut rw = VlqWriter::new();
        write_registers(&mut rw, &regs).unwrap();
        let reg_bytes = rw.result();

        let err = ErgoBoxCandidate::try_from_raw_parts(
            1_000_000,
            tree_b,
            tree_a_bytes,
            100,
            vec![],
            regs,
            reg_bytes,
        )
        .unwrap_err();
        let WriteError::InvalidData(msg) = &err;
        assert!(
            msg.contains("different tree"),
            "msg should describe mismatch, got: {msg}",
        );
    }

    #[test]
    fn try_from_raw_parts_rejects_trailing_tree_bytes() {
        let tree = size_delimited_tree();
        let mut tw = VlqWriter::new();
        crate::ergo_tree::write_ergo_tree(&mut tw, &tree).unwrap();
        let mut tree_bytes = tw.result();
        tree_bytes.push(0x00); // trailing byte

        let regs = AdditionalRegisters::empty();
        let mut rw = VlqWriter::new();
        write_registers(&mut rw, &regs).unwrap();
        let reg_bytes = rw.result();

        let err = ErgoBoxCandidate::try_from_raw_parts(
            1_000_000,
            tree,
            tree_bytes,
            100,
            vec![],
            regs,
            reg_bytes,
        )
        .unwrap_err();
        let WriteError::InvalidData(msg) = &err;
        assert!(
            msg.contains("trailing"),
            "msg should mention trailing, got: {msg}"
        );
    }
}
