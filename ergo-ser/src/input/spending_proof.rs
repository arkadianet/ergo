//! [`SpendingProof`] and signed [`Input`]: sigma proof bytes plus the
//! committed context extension, with verbatim-bytes round-trip guarantees
//! and the `bytes_to_sign` (zeroed-proof) serialization form.

use ergo_primitives::digest::Digest32;
use ergo_primitives::reader::{ReadError, VlqReader};
use ergo_primitives::writer::VlqWriter;

use crate::error::WriteError;

use super::context_extension::{read_context_extension, write_context_extension, ContextExtension};

/// Sigma proof bytes plus the context extension committed to during
/// signing.
///
/// The verbatim wire bytes of the extension are kept alongside the
/// parsed [`ContextExtension`] so callers that need byte-exact round-trip
/// (`bytes_to_sign(tx)` parity, raw mainnet fixture replay) don't have
/// to re-serialize through the writer — which can canonicalize away
/// non-canonical-but-accepted forms (e.g. SBoolean wire `0105` vs `0101`).
#[derive(Debug, Clone, PartialEq)]
pub struct SpendingProof {
    /// Raw signature / sigma proof bytes.
    pub proof: Vec<u8>,
    /// Parsed context extension committed to by `proof`. Kept in sync with the
    /// private `extension_bytes` cache that every writer emits — so it is
    /// `pub(crate)` (read via [`SpendingProof::extension`], mutate only through
    /// the constructors) rather than `pub`: external mutation of
    /// `extension.values` would desync `bytes_to_sign` / serialization (which
    /// use the cached bytes) from inspection.
    pub(crate) extension: ContextExtension,
    extension_bytes: Vec<u8>,
}

impl SpendingProof {
    /// Borrow the parsed context extension committed to by `proof`. Read-only:
    /// the wire-byte cache (`extension_bytes`) is fixed at construction, so
    /// mutation would desync serialization — rebuild via [`SpendingProof::new`]
    /// (or a `from_*_raw_parts` constructor) to change the extension.
    pub fn extension(&self) -> &ContextExtension {
        &self.extension
    }

    /// Build a `SpendingProof` from `(proof, extension)`, serializing
    /// the extension to its canonical wire form internally. Use this on
    /// the construct-and-sign path where no externally-supplied byte
    /// fixture exists.
    pub fn new(proof: Vec<u8>, extension: ContextExtension) -> Result<Self, WriteError> {
        let mut w = VlqWriter::new();
        write_context_extension(&mut w, &extension)?;
        let extension_bytes = w.result();
        Ok(Self {
            proof,
            extension,
            extension_bytes,
        })
    }

    /// Build a SpendingProof from a parsed [`ContextExtension`] and the
    /// **verbatim** wire bytes the parser saw. Use this when reconstructing
    /// from external data (REST JSON, captured fixtures) where the original
    /// byte form must be preserved for `bytes_to_sign(tx)` parity.
    ///
    /// # Safety contract
    ///
    /// Caller MUST ensure `extension_bytes` is a valid serialization that
    /// `read_context_extension` would parse back to the same `extension`
    /// struct. No runtime validation is performed — the trade-off for
    /// byte-exact roundtrip on Scala-emitted forms that the writer
    /// might canonicalize away (e.g. SBoolean `0105` vs `0101`). A
    /// mismatch silently desyncs `bytes_to_sign(tx)` from internal
    /// inspection. Prefer [`SpendingProof::try_from_raw_parts`] when
    /// the caller cannot guarantee the contract, or
    /// [`SpendingProof::new`] when no external byte fixture exists.
    pub fn from_trusted_raw_parts(
        proof: Vec<u8>,
        extension: ContextExtension,
        extension_bytes: Vec<u8>,
    ) -> Self {
        Self {
            proof,
            extension,
            extension_bytes,
        }
    }

    /// Validating counterpart to [`SpendingProof::from_trusted_raw_parts`].
    ///
    /// Re-parses `extension_bytes` and checks the result equals the
    /// supplied `extension`. Returns `WriteError::InvalidData` on
    /// re-parse failure, trailing bytes, or parsed-mismatch. On
    /// success the proof carries the supplied bytes verbatim, so
    /// non-canonical Scala-emitted extension forms (SBoolean `0105`
    /// vs `0101`) are preserved for `bytes_to_sign(tx)` parity.
    ///
    /// Cost: one re-parse per call. Use on construction paths where
    /// the caller cannot prove the invariant by construction; prefer
    /// the unchecked [`SpendingProof::from_trusted_raw_parts`] in
    /// hot paths where bytes/parsed are produced atomically by the
    /// same reader (e.g. inside `read_spending_proof`).
    pub fn try_from_raw_parts(
        proof: Vec<u8>,
        extension: ContextExtension,
        extension_bytes: Vec<u8>,
    ) -> Result<Self, WriteError> {
        let mut r = VlqReader::new(&extension_bytes);
        let parsed = read_context_extension(&mut r)
            .map_err(|e| WriteError::InvalidData(format!("extension_bytes do not parse: {e}")))?;
        if !r.is_empty() {
            return Err(WriteError::InvalidData(
                "extension_bytes have trailing content after parse".into(),
            ));
        }
        if parsed != extension {
            return Err(WriteError::InvalidData(
                "extension_bytes parse to a different ContextExtension than the supplied parsed value".into(),
            ));
        }
        Ok(Self {
            proof,
            extension,
            extension_bytes,
        })
    }

    /// Verbatim wire bytes of the context extension (count byte +
    /// concatenated entries). Preserved across parse so callers needing
    /// byte-exact roundtrip — including parity encoders — don't have to
    /// re-serialize.
    pub fn extension_bytes(&self) -> &[u8] {
        &self.extension_bytes
    }
}

/// Serialize a [`SpendingProof`]: VLQ-`u16` proof length, raw proof
/// bytes, then the verbatim context-extension bytes captured at parse
/// (or built fresh by [`SpendingProof::new`]).
pub fn write_spending_proof(w: &mut VlqWriter, sp: &SpendingProof) -> Result<(), WriteError> {
    // Scala writes the proof length as a u16; a proof above 65535 bytes
    // would silently wrap on `as u16`. Real sigma proofs are far smaller
    // but the cap is the wire-format constraint. REST callers reach this
    // via decode_input_with_mode without pre-validating proof length, so
    // surface as WriteError instead of panicking.
    if sp.proof.len() > u16::MAX as usize {
        return Err(WriteError::InvalidData(format!(
            "SpendingProof proof too long for Scala wire format: {} bytes (max 65535)",
            sp.proof.len()
        )));
    }
    w.put_u16(sp.proof.len() as u16);
    w.put_bytes(&sp.proof);
    w.put_bytes(&sp.extension_bytes);
    Ok(())
}

/// Decode the wire form produced by [`write_spending_proof`]. The
/// extension bytes consumed during parse are captured verbatim so the
/// resulting [`SpendingProof`] is byte-exact-roundtrip.
pub fn read_spending_proof(r: &mut VlqReader) -> Result<SpendingProof, ReadError> {
    let proof_len = r.get_u16()? as usize;
    let proof = r.get_bytes(proof_len)?.to_vec();
    let ext_start = r.position();
    let extension = read_context_extension(r)?;
    let ext_end = r.position();
    let extension_bytes = r.data_slice(ext_start, ext_end).to_vec();
    Ok(SpendingProof {
        proof,
        extension,
        extension_bytes,
    })
}

/// Signed spending input: 32-byte `box_id` followed by a
/// [`SpendingProof`].
#[derive(Debug, Clone, PartialEq)]
pub struct Input {
    /// Identifier of the box being spent.
    pub box_id: Digest32,
    /// Sigma proof + committed context extension.
    pub spending_proof: SpendingProof,
}

/// Serialize an [`Input`] as 32-byte `box_id` followed by the spending
/// proof wire form.
pub fn write_input(w: &mut VlqWriter, input: &Input) -> Result<(), WriteError> {
    w.put_bytes(input.box_id.as_bytes());
    write_spending_proof(w, &input.spending_proof)?;
    Ok(())
}

/// Decode the wire form produced by [`write_input`].
pub fn read_input(r: &mut VlqReader) -> Result<Input, ReadError> {
    let box_id = Digest32::from_bytes(r.get_array::<32>()?);
    let spending_proof = read_spending_proof(r)?;
    Ok(Input {
        box_id,
        spending_proof,
    })
}

/// Serialize an input in `bytes_to_sign` form: 32-byte `box_id`,
/// then a `u16 = 0` (zeroed proof length), then the verbatim extension
/// bytes. Matches Scala's `Input.bytesWithoutProof` — what the signer
/// hashes to bind the proof to the rest of the tx.
pub fn write_input_to_sign(w: &mut VlqWriter, input: &Input) -> Result<(), WriteError> {
    w.put_bytes(input.box_id.as_bytes());
    w.put_u16(0); // empty proof
    w.put_bytes(&input.spending_proof.extension_bytes);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sigma_type::SigmaType;
    use crate::sigma_value::SigmaValue;

    // ----- helpers -----

    fn make_box_id(fill: u8) -> Digest32 {
        Digest32::from_bytes([fill; 32])
    }

    fn roundtrip_result<T: PartialEq + std::fmt::Debug>(
        write_fn: fn(&mut VlqWriter, &T) -> Result<(), WriteError>,
        read_fn: fn(&mut VlqReader) -> Result<T, ReadError>,
        val: &T,
    ) {
        let mut w = VlqWriter::new();
        write_fn(&mut w, val).unwrap();
        let data = w.result();
        let mut r = VlqReader::new(&data);
        let decoded = read_fn(&mut r).unwrap();
        assert!(r.is_empty(), "leftover bytes after roundtrip");
        assert_eq!(&decoded, val);
    }

    // ----- round-trips -----

    #[test]
    fn input_roundtrip() {
        let mut ext = ContextExtension::empty();
        ext.values.insert(0, (SigmaType::SInt, SigmaValue::Int(99)));
        ext.values.insert(
            5,
            (
                SigmaType::SColl(Box::new(SigmaType::SByte)),
                SigmaValue::Coll(crate::sigma_value::CollValue::Bytes(vec![1, 2, 3])),
            ),
        );

        let input = Input {
            box_id: make_box_id(0xFF),
            spending_proof: SpendingProof::new(vec![0xCA, 0xFE, 0xBA, 0xBE], ext).unwrap(),
        };
        roundtrip_result(write_input, read_input, &input);
    }

    #[test]
    fn extension_accessor_stays_coherent_with_cached_bytes() {
        // Regression for the desync footgun: `extension` is `pub(crate)` and
        // externally reachable only read-only via `extension()`, so external
        // code cannot mutate `extension.values` out of sync with the private
        // `extension_bytes` that every writer (serialization, `bytes_to_sign`)
        // emits. Pin that construction keeps them coherent and the accessor
        // reflects the parsed extension through a full round-trip.
        let mut ext = ContextExtension::empty();
        ext.values
            .insert(7, (SigmaType::SInt, SigmaValue::Int(123)));
        let input = Input {
            box_id: make_box_id(0x11),
            spending_proof: SpendingProof::new(vec![0xAA, 0xBB], ext.clone()).unwrap(),
        };
        assert_eq!(input.spending_proof.extension(), &ext);
        // The writer-emitted bytes re-parse to the same extension — the cache
        // the writer used is coherent with what the accessor reports.
        let mut w = VlqWriter::new();
        write_input(&mut w, &input).unwrap();
        let bytes = w.result();
        let mut r = VlqReader::new(&bytes);
        let parsed = read_input(&mut r).unwrap();
        assert_eq!(parsed.spending_proof.extension(), &ext);
    }

    #[test]
    fn bytes_to_sign_zeroes_proof_preserves_extension() {
        let mut ext = ContextExtension::empty();
        ext.values.insert(0, (SigmaType::SInt, SigmaValue::Int(42)));

        let input = Input {
            box_id: make_box_id(0xAA),
            spending_proof: SpendingProof::new(vec![0x01, 0x02, 0x03, 0x04, 0x05], ext.clone())
                .unwrap(),
        };

        // Full serialization includes proof bytes
        let mut w_full = VlqWriter::new();
        write_input(&mut w_full, &input).unwrap();
        let full_bytes = w_full.result();

        // bytes_to_sign serialization has empty proof but same extension
        let mut w_sign = VlqWriter::new();
        write_input_to_sign(&mut w_sign, &input).unwrap();
        let sign_bytes = w_sign.result();

        // Both start with same 32-byte box_id
        assert_eq!(&full_bytes[..32], &sign_bytes[..32]);

        // Full bytes are longer because they contain proof data
        assert!(full_bytes.len() > sign_bytes.len());

        // Parse the bytes_to_sign output manually to verify structure
        let mut r = VlqReader::new(&sign_bytes);
        let box_id_bytes = r.get_bytes(32).unwrap();
        assert_eq!(box_id_bytes, &[0xAA; 32]);

        // Proof length should be 0 (VLQ-encoded as single byte 0x00)
        let proof_len = r.get_u16().unwrap();
        assert_eq!(proof_len, 0);

        // Extension should still be present and match the original
        let decoded_ext = read_context_extension(&mut r).unwrap();
        assert!(r.is_empty());
        assert_eq!(decoded_ext, ext);
    }

    #[test]
    fn spending_proof_empty_proof_roundtrip() {
        let sp = SpendingProof::new(vec![], ContextExtension::empty()).unwrap();
        roundtrip_result(write_spending_proof, read_spending_proof, &sp);
    }

    // ----- error paths -----

    #[test]
    fn write_spending_proof_above_u16_returns_invalid_data() {
        // A 65536-byte proof is well above any real sigma-proof
        // length, but REST `decode_input_with_mode` pulls the proof
        // straight from JSON hex with no length pre-check. The
        // writer must surface this as a recoverable WriteError so
        // the panic path stays closed for caller-supplied data.
        let sp = SpendingProof::new(vec![0u8; u16::MAX as usize + 1], ContextExtension::empty())
            .unwrap();
        let mut w = VlqWriter::new();
        let err = write_spending_proof(&mut w, &sp).unwrap_err();
        let WriteError::InvalidData(msg) = &err;
        assert!(
            msg.contains("65536"),
            "message should name the length, got: {msg}"
        );
        assert!(
            msg.contains("max"),
            "message should name the cap, got: {msg}"
        );
    }

    fn ext_with(key: u8, val: i32) -> ContextExtension {
        let mut values = indexmap::IndexMap::new();
        values.insert(key, (SigmaType::SInt, SigmaValue::Int(val)));
        ContextExtension { values }
    }

    fn serialize_ext(ext: &ContextExtension) -> Vec<u8> {
        let mut w = VlqWriter::new();
        write_context_extension(&mut w, ext).unwrap();
        w.result()
    }

    #[test]
    fn try_from_raw_parts_accepts_matching_bytes() {
        let ext = ext_with(0, 42);
        let bytes = serialize_ext(&ext);
        let sp = SpendingProof::try_from_raw_parts(vec![0xDE, 0xAD], ext.clone(), bytes.clone())
            .expect("matching bytes/parsed must succeed");
        assert_eq!(sp.extension_bytes(), &bytes[..]);
        assert_eq!(sp.extension, ext);
    }

    #[test]
    fn try_from_raw_parts_rejects_mismatched_extension() {
        // Build bytes for ext_a, supply ext_b as the parsed value.
        let ext_a = ext_with(0, 1);
        let ext_b = ext_with(0, 2);
        let bytes_a = serialize_ext(&ext_a);
        let err = SpendingProof::try_from_raw_parts(vec![], ext_b, bytes_a).unwrap_err();
        let WriteError::InvalidData(msg) = &err;
        assert!(
            msg.contains("different ContextExtension"),
            "msg should describe mismatch, got: {msg}",
        );
    }

    #[test]
    fn try_from_raw_parts_rejects_garbage_extension_bytes() {
        let err = SpendingProof::try_from_raw_parts(
            vec![],
            ContextExtension::empty(),
            vec![0xFF, 0x80], // count=255, then trailing nonsense the entry parser will choke on
        )
        .unwrap_err();
        let WriteError::InvalidData(msg) = &err;
        assert!(
            msg.contains("extension_bytes"),
            "msg should name field, got: {msg}"
        );
    }

    #[test]
    fn try_from_raw_parts_rejects_trailing_extension_bytes() {
        let ext = ext_with(0, 1);
        let mut bytes = serialize_ext(&ext);
        bytes.push(0x00); // trailing byte
        let err = SpendingProof::try_from_raw_parts(vec![], ext, bytes).unwrap_err();
        let WriteError::InvalidData(msg) = &err;
        assert!(
            msg.contains("trailing"),
            "msg should mention trailing, got: {msg}"
        );
    }
}
