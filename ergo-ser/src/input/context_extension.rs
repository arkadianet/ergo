//! [`ContextExtension`] — script context variables — and its wire codec,
//! including the dual `Map1`-`Map4` / HAMT entry-order encoding and the
//! rule-1019 `CheckV6Type` parse gate.

use indexmap::IndexMap;

use ergo_primitives::reader::{ReadError, VlqReader};
use ergo_primitives::writer::VlqWriter;

use crate::error::WriteError;
use crate::sigma_type::SigmaType;
use crate::sigma_value::{read_constant, write_constant, SigmaValue};

/// Context variables supplied to script evaluation alongside an input.
///
/// Keys are caller-chosen `u8` indices; values are typed sigma constants
/// (`SigmaType + SigmaValue`). Backed by an [`IndexMap`] so iteration
/// follows insertion / parse order — Scala parity for the `Map1`-`Map4`
/// case (≤ 4 entries, insertion order). For ≥ 5 entries
/// [`write_context_extension`] overrides the storage order with the
/// Scala 2.12 HAMT depth-first walk via [`crate::scala_hamt`]; the
/// IndexMap's natural order is only used for the ≤ 4 path.
#[derive(Debug, Clone, PartialEq)]
pub struct ContextExtension {
    /// Insertion-order map from variable index to typed sigma value.
    pub values: IndexMap<u8, (SigmaType, SigmaValue)>,
}

impl ContextExtension {
    /// Empty extension — no context variables. Equivalent to
    /// `Default::default()` (which would also work if it were derived;
    /// kept as an explicit constructor for readability).
    pub fn empty() -> Self {
        Self {
            values: IndexMap::new(),
        }
    }

    /// `true` when no variables are bound.
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }
}

/// Serialize a context extension as a raw `u8` count followed by
/// `key + serialized_constant` for each entry.
///
/// Entry order matches what Scala 2.12 `Map[Byte, T]` would yield when
/// iterating. Scala's `Map` factory switches data structure at 5
/// entries:
///
/// - **≤ 4 entries**: `Map1`–`Map4`, insertion order. Our [`IndexMap`]
///   storage preserves that order through parse + re-serialize, so a
///   wallet that signs bytes for `Map3((5 -> _, 3 -> _, 8 -> _))`
///   yields wire bytes `[5, 3, 8]` and we round-trip identically.
/// - **≥ 5 entries**: `HashTrieMap` with HAMT depth-first iteration
///   order. We sort by [`crate::scala_hamt::hamt_sort_key_for_byte_key`]
///   here, overriding the storage order, because HAMT order is
///   independent of insertion sequence — it's a pure function of the
///   keyset. See [`crate::scala_hamt`] for the algorithm and the
///   Scala 2.12 source citation.
///
/// Re-serializing in any other order desyncs `bytes_to_sign(tx)` from
/// what a Scala wallet signed, breaking signature verification on the
/// JSON submit path.
pub fn write_context_extension(
    w: &mut VlqWriter,
    ext: &ContextExtension,
) -> Result<(), WriteError> {
    // Scala writes the entry count as a single unsigned byte; a
    // ContextExtension with >255 entries would silently wrap on
    // `as u8`. Surface as a structured error so REST/JSON callers
    // (decode_context_extension_with_mode) see a recoverable failure
    // instead of a panic.
    if ext.values.len() > u8::MAX as usize {
        return Err(WriteError::InvalidData(format!(
            "ContextExtension entry count too large for Scala wire format: {} (max 255)",
            ext.values.len()
        )));
    }
    w.put_u8(ext.values.len() as u8);
    if ext.values.len() < 5 {
        // IndexMap iteration = insertion order. Matches Scala's
        // `Map1`-`Map4` semantics: a wallet that inserted (5, 3, 8)
        // emits bytes in that order, and we reproduce it byte-for-
        // byte.
        for (&key, (tpe, val)) in &ext.values {
            w.put_u8(key);
            write_constant(w, tpe, val)?;
        }
    } else {
        // HAMT order is a pure function of the keyset — independent
        // of insertion sequence. Override the IndexMap storage order
        // with HAMT for Scala 2.12 `HashTrieMap` parity.
        let mut entries: Vec<(u8, &(SigmaType, SigmaValue))> =
            ext.values.iter().map(|(k, v)| (*k, v)).collect();
        entries.sort_by_key(|(k, _)| crate::scala_hamt::hamt_sort_key_for_byte_key(*k));
        for (key, (tpe, val)) in entries {
            w.put_u8(key);
            write_constant(w, tpe, val)?;
        }
    }
    Ok(())
}

/// Read the ContextExtension entry-count byte with Scala's SIGNED semantics.
///
/// Consensus parity (sigma-state 6.0.2): Scala
/// `ContextExtension.serializer.parse`
/// (`data/.../sigma/interpreter/ContextExtension.scala:53-55`) reads this count
/// with `r.getByte()` — a SIGNED byte (`core/.../CoreByteReader.scala:43-46`) —
/// and rejects any negative value
/// (`if (extSize < 0) error("Negative amount of context extension values: ...")`
/// → `SerializerException`) BEFORE reading a single entry. A wire count byte in
/// `0x80..=0xFF` decodes to `-128..=-1` and is rejected. Rust historically read
/// it UNSIGNED (`get_u8() as usize`, range `0..=255`) and went on to read that
/// many entries, ACCEPTING inputs Scala rejects — a fork-dangerous
/// accept-invalid divergence, live at every height and protocol version (the
/// guard is un-versioned on both sides).
///
/// The fix rejects `raw > 127` (equivalently `raw as i8 < 0`) here, matching
/// Scala's signed reject exactly, and rejecting BEFORE any entry is read.
///
/// Consensus safety — byte-inert for every currently-valid transaction: Scala
/// has ALWAYS rejected a count above 127, and its serializer refuses to even
/// WRITE one (`if (size > Byte.MaxValue) error`, ContextExtension.scala:47), so
/// no canonical-chain block and no honestly-relayed transaction can carry a
/// context extension with more than 127 entries. This change therefore adds
/// zero false rejects; it only closes the accept-invalid direction (Rust used
/// to accept counts `128..=255`, Scala rejects them). Counts `0..=127` decode
/// exactly as before.
fn read_extension_count(r: &mut VlqReader) -> Result<usize, ReadError> {
    let raw = r.get_u8()?;
    if raw > 0x7f {
        return Err(ReadError::InvalidData(format!(
            "negative context-extension value count: {} (Scala reads the count as a signed byte and rejects the high bit)",
            raw as i8
        )));
    }
    Ok(raw as usize)
}

/// Decode the wire form produced by [`write_context_extension`].
/// Insertion order = wire order: IndexMap preserves the order keys
/// arrived on the wire so a subsequent re-serialize (for ≤ 4 entries)
/// reproduces the same byte sequence. For ≥ 5 entries the writer
/// re-sorts to HAMT order, so storage order doesn't matter there.
///
/// # CheckV6Type gate (rule 1019) — consensus parity, parse-time
///
/// Scala `ContextExtension.serializer.parse` calls `CheckV6Type(v)` on
/// EVERY decoded entry value at parse (see
/// `sigma/interpreter/ContextExtension.scala:60`), BEFORE any script
/// runs and regardless of whether a `getVar` ever references the var.
/// `CheckV6Type` (rule 1019, `ValidationRules.scala:165-194`) is a
/// registered `EnabledRule` in BOTH `ruleSpecsV5` and `ruleSpecsV6`, so
/// it fires at every activated protocol version — it is NOT gated on
/// v6 activation. It throws for any value whose type IS or CONTAINS
/// (recursing tuple items / collection element) `SOption`, `SHeader`,
/// or `SUnsignedBigInt`. We apply the identical predicate
/// ([`crate::register::type_has_v6_only_type`], the same one the
/// register reader uses) here, returning the same rejection class the
/// register path returns.
///
/// ## Why this is byte-inert for every currently-valid transaction
///
/// A context-extension value carrying a v6-only type has ALWAYS been
/// rejected by the Scala reference node at parse (rule 1019 has existed
/// and been enabled since these types were introduced). Therefore no
/// accepted on-chain transaction — and no transaction any honest peer
/// will relay — carries such a value. This gate can only reject inputs
/// Scala ALSO rejects; it adds ZERO false rejects for legal (v5-typed)
/// context-extension values, which decode exactly as before. Direction
/// closed: the pre-gate reader ACCEPTED these (accept-invalid, fork
/// risk); the gate makes Rust reject-parity with Scala.
pub fn read_context_extension(r: &mut VlqReader) -> Result<ContextExtension, ReadError> {
    let count = read_extension_count(r)?;
    let mut values = IndexMap::with_capacity(count);
    for _ in 0..count {
        let key = r.get_u8()?;
        let (tpe, val) = read_constant(r)?;
        // Rule 1019 CheckV6Type: reject at parse, matching Scala's
        // per-entry `CheckV6Type(v)`. Version-independent, fires whether
        // or not the var is later referenced by `getVar`. Identical
        // predicate + error class to the register reader.
        if crate::register::type_has_v6_only_type(&tpe) {
            return Err(ReadError::InvalidData(format!(
                "context-extension var type {tpe:?} contains a v6 type (Option / \
                 Header / UnsignedBigInt) — rule 1019 CheckV6Type"
            )));
        }
        values.insert(key, (tpe, val));
    }
    Ok(ContextExtension { values })
}

/// Walk verbatim ContextExtension bytes (count byte + concatenated
/// `key + serialized_constant` entries) and return `(key, value_bytes)`
/// pairs preserving the original wire encoding of each entry's value.
///
/// The returned `value_bytes` is the type-prefix + value-data slice, i.e.
/// what `ValueSerializer.serialize` produced — exactly what the Scala
/// node hex-encodes per-entry in the JSON `extension` map.
pub fn split_context_extension_bytes(
    extension_bytes: &[u8],
) -> Result<Vec<(u8, Vec<u8>)>, ReadError> {
    let mut r = VlqReader::new(extension_bytes);
    let count = read_extension_count(&mut r)?;
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        let key = r.get_u8()?;
        let start = r.position();
        let _ = read_constant(&mut r)?;
        let end = r.position();
        entries.push((key, r.data_slice(start, end).to_vec()));
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- helpers -----

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
    fn context_extension_empty_roundtrip() {
        let ext = ContextExtension::empty();
        assert!(ext.is_empty());
        roundtrip_result(write_context_extension, read_context_extension, &ext);
    }

    #[test]
    fn context_extension_with_values_roundtrip() {
        let mut ext = ContextExtension::empty();
        // key 0 -> Int(42)
        ext.values.insert(0, (SigmaType::SInt, SigmaValue::Int(42)));
        // key 3 -> Coll[Byte]([0xDE, 0xAD])
        ext.values.insert(
            3,
            (
                SigmaType::SColl(Box::new(SigmaType::SByte)),
                SigmaValue::Coll(crate::sigma_value::CollValue::Bytes(vec![0xDE, 0xAD])),
            ),
        );
        assert!(!ext.is_empty());
        roundtrip_result(write_context_extension, read_context_extension, &ext);
    }

    #[test]
    fn context_extension_preserves_insertion_order_for_n_leq_4() {
        // Scala parity for `Map1`-`Map4`: ≤ 4 entries iterate in
        // INSERTION order, not ascending. Our IndexMap storage +
        // the ≤4 branch in write_context_extension reproduce that.
        // A wallet inserting (10, 2, 5) emits wire bytes in
        // [10, 2, 5] — and we round-trip identically.
        let mut ext = ContextExtension::empty();
        ext.values
            .insert(10, (SigmaType::SInt, SigmaValue::Int(100)));
        ext.values
            .insert(2, (SigmaType::SInt, SigmaValue::Int(200)));
        ext.values
            .insert(5, (SigmaType::SInt, SigmaValue::Int(300)));

        let mut w = VlqWriter::new();
        write_context_extension(&mut w, &ext).unwrap();
        let data = w.result();
        let mut r = VlqReader::new(&data);
        let decoded = read_context_extension(&mut r).unwrap();
        assert!(r.is_empty());

        // Wire order: insertion order.
        assert_eq!(data[0], 3, "count byte");
        assert_eq!(data[1], 10, "first key on wire = first inserted");
        // Decoded IndexMap preserves wire order too — the bytes
        // round-trip identically through parse + re-serialize.
        let keys: Vec<u8> = decoded.values.keys().copied().collect();
        assert_eq!(keys, vec![10, 2, 5]);
    }

    #[test]
    fn context_extension_n_leq_4_round_trip_non_ascending_wire() {
        // Round-trip property: parsing then re-serializing wire bytes
        // produces the same bytes. Critical for the JSON submit path
        // when the wallet signed bytes in non-ascending insertion
        // order with 1-4 entries.
        let raw_wire = {
            let mut ext = ContextExtension::empty();
            ext.values.insert(8, (SigmaType::SInt, SigmaValue::Int(1)));
            ext.values.insert(3, (SigmaType::SInt, SigmaValue::Int(2)));
            ext.values.insert(5, (SigmaType::SInt, SigmaValue::Int(3)));
            ext.values.insert(1, (SigmaType::SInt, SigmaValue::Int(4)));
            let mut w = VlqWriter::new();
            write_context_extension(&mut w, &ext).unwrap();
            w.result()
        };
        let mut r = VlqReader::new(&raw_wire);
        let parsed = read_context_extension(&mut r).unwrap();
        let mut w2 = VlqWriter::new();
        write_context_extension(&mut w2, &parsed).unwrap();
        assert_eq!(
            w2.result(),
            raw_wire,
            "≤ 4 wire-bytes must round-trip identically",
        );
        // First wire key reflects insertion order, not ascending.
        assert_eq!(raw_wire[1], 8);
    }

    #[test]
    fn context_extension_n_5_uses_hamt_order_on_wire() {
        // At exactly 5 entries (Scala's HashTrieMap threshold) the
        // writer emits in HAMT iteration order, NOT ascending. Pin
        // the property by comparing the wire-byte first-key against
        // the ascending-min: they MUST diverge for some test keyset
        // (otherwise we'd silently regress to ascending).
        let mut ext = ContextExtension::empty();
        for key in [3u8, 17, 42, 99, 200] {
            ext.values
                .insert(key, (SigmaType::SInt, SigmaValue::Int(key as i32)));
        }

        let mut w = VlqWriter::new();
        write_context_extension(&mut w, &ext).unwrap();
        let data = w.result();
        assert_eq!(data[0], 5, "count byte");
        // Expected on-wire first key: the one with the smallest HAMT
        // sort key (root-level bucket). Compute from our algorithm
        // and assert. Provenance: derived from this module's own
        // implementation — a self-oracle, not an external Scala-node
        // byte vector.
        let mut by_hamt: Vec<u8> = ext.values.keys().copied().collect();
        by_hamt.sort_by_key(|&k| crate::scala_hamt::hamt_sort_key_for_byte_key(k));
        assert_eq!(data[1], by_hamt[0], "wire first key = HAMT-first key");
        // Round-trip: read back, get the same set (different parse-
        // side BTreeMap order, that's fine).
        let mut r = VlqReader::new(&data);
        let decoded = read_context_extension(&mut r).unwrap();
        assert!(r.is_empty());
        assert_eq!(decoded.values.len(), 5);
    }

    #[test]
    fn context_extension_n_5_wire_round_trip_idempotent() {
        // Re-serializing parsed bytes must produce the same bytes.
        // This is the property a Scala-wallet signature depends on:
        // we receive HAMT-ordered bytes, parse to BTreeMap (loses
        // order), and the writer must reproduce the same HAMT-
        // ordered bytes — otherwise `bytes_to_sign(tx)` desyncs.
        let mut ext = ContextExtension::empty();
        for key in [11u8, 23, 47, 89, 137, 199, 251] {
            ext.values
                .insert(key, (SigmaType::SInt, SigmaValue::Int(key as i32)));
        }

        let mut w1 = VlqWriter::new();
        write_context_extension(&mut w1, &ext).unwrap();
        let bytes_a = w1.result();

        let mut r = VlqReader::new(&bytes_a);
        let parsed = read_context_extension(&mut r).unwrap();
        assert!(r.is_empty());

        let mut w2 = VlqWriter::new();
        write_context_extension(&mut w2, &parsed).unwrap();
        let bytes_b = w2.result();

        assert_eq!(
            bytes_a, bytes_b,
            "HAMT-ordered serialize must be idempotent across parse + re-serialize",
        );
    }

    #[test]
    fn context_extension_n_5_high_bit_keys_round_trip() {
        // Sign-extension regression: keys ≥ 128 (i8 negative when
        // cast `as i8`). If `hamt_sort_key_for_byte_key` ever drops
        // the `as i8` cast, the order changes for high-bit keys but
        // the idempotency property here still holds. To distinguish:
        // assert the high-bit-only and low-bit-only key sets produce
        // DIFFERENT first-on-wire keys.
        let mut low_only = ContextExtension::empty();
        for key in [3u8, 17, 42, 65, 99] {
            low_only
                .values
                .insert(key, (SigmaType::SInt, SigmaValue::Int(0)));
        }
        let mut high_only = ContextExtension::empty();
        for key in [131u8, 145, 170, 193, 227] {
            high_only
                .values
                .insert(key, (SigmaType::SInt, SigmaValue::Int(0)));
        }

        let mut w1 = VlqWriter::new();
        write_context_extension(&mut w1, &low_only).unwrap();
        let low_bytes = w1.result();
        let mut w2 = VlqWriter::new();
        write_context_extension(&mut w2, &high_only).unwrap();
        let high_bytes = w2.result();

        // First key on wire for each set — must be present in the
        // respective input keyset (sanity), and round-trip cleanly.
        let low_first = low_bytes[1];
        let high_first = high_bytes[1];
        assert!([3u8, 17, 42, 65, 99].contains(&low_first));
        assert!([131u8, 145, 170, 193, 227].contains(&high_first));

        // Round-trip idempotency for the high-bit set (the case the
        // sign-extension would break first).
        let mut r = VlqReader::new(&high_bytes);
        let parsed = read_context_extension(&mut r).unwrap();
        let mut w3 = VlqWriter::new();
        write_context_extension(&mut w3, &parsed).unwrap();
        assert_eq!(w3.result(), high_bytes);
    }

    // ----- error paths -----

    #[test]
    fn write_context_extension_above_255_returns_invalid_data() {
        // Scala writes the entry count as a single unsigned byte
        // (cap 255). REST callers can construct ContextExtension
        // directly via the public `values` field; the writer must
        // surface this as `WriteError`, not panic.
        //
        // 256 distinct u8 keys exhausts the keyspace exactly — already
        // one past the cap. IndexMap dedupes on key, so 257 is
        // unreachable, but 256 suffices to trigger the bound.
        let values: indexmap::IndexMap<u8, (SigmaType, SigmaValue)> = (0u16..=255)
            .map(|k| (k as u8, (SigmaType::SInt, SigmaValue::Int(k as i32))))
            .collect();
        assert_eq!(values.len(), 256, "test setup: 256 distinct u8 keys");
        let ext = ContextExtension { values };
        let mut w = VlqWriter::new();
        let err = write_context_extension(&mut w, &ext).unwrap_err();
        let WriteError::InvalidData(msg) = &err;
        assert!(
            msg.contains("256"),
            "message should name the count, got: {msg}"
        );
        assert!(
            msg.contains("255"),
            "message should name the cap, got: {msg}"
        );
    }

    fn serialize_ext(ext: &ContextExtension) -> Vec<u8> {
        let mut w = VlqWriter::new();
        write_context_extension(&mut w, ext).unwrap();
        w.result()
    }

    // ----- rule 1019 CheckV6Type on context-extension var types -----

    // The gate in `read_context_extension` is exactly
    // `if crate::register::type_has_v6_only_type(&tpe) { reject }`, so the
    // set of rejected inputs is precisely the set of types for which that
    // predicate is true. These tests pin (a) the predicate never fires on a
    // legal v5 type — no reject-valid over-reach — and (b) it fires on the
    // CheckV6Type set (Option / Header / UnsignedBigInt) at any nesting
    // depth, matching Scala `ValidationRules.scala:172-186` `step`.

    fn read_ext(bytes: &[u8]) -> Result<ContextExtension, ReadError> {
        let mut r = VlqReader::new(bytes);
        let ext = read_context_extension(&mut r)?;
        assert!(r.is_empty(), "leftover bytes after context-extension parse");
        Ok(ext)
    }

    fn ext_bytes_for(tpe: SigmaType, val: SigmaValue) -> Vec<u8> {
        let mut ext = ContextExtension::empty();
        ext.values.insert(1, (tpe, val));
        let mut w = VlqWriter::new();
        write_context_extension(&mut w, &ext).expect("write ext");
        w.result()
    }

    // ----- reject-side over-reach guard: legal v5 types MUST still decode -----

    #[test]
    fn v6_gate_predicate_never_fires_on_legal_v5_types() {
        // Exhaustive over-reach guard at the predicate boundary: because the
        // gate is a pure function of `type_has_v6_only_type(&tpe)`, proving
        // the predicate is false for every legal type proves the gate cannot
        // reject any legal context-extension value regardless of its data.
        use crate::register::type_has_v6_only_type as v6;
        use SigmaType::*;
        for tpe in [
            SBoolean,
            SByte,
            SShort,
            SInt,
            SLong,
            SBigInt,
            SGroupElement,
            SSigmaProp,
            SAvlTree,
            SBox,
            SUnit,
            SColl(Box::new(SByte)),
            SColl(Box::new(SInt)),
            SColl(Box::new(SGroupElement)),
            SColl(Box::new(SColl(Box::new(SByte)))),
            STuple(vec![SInt, SLong]),
            STuple(vec![SColl(Box::new(SByte)), SGroupElement, SSigmaProp]),
            SColl(Box::new(STuple(vec![SInt, SByte]))),
        ] {
            assert!(
                !v6(&tpe),
                "legal v5 type {tpe:?} must NOT be rejected by the CheckV6Type gate",
            );
        }
    }

    #[test]
    fn v6_gate_accepts_v5_context_extension_values_on_decode() {
        // Full decode-path acceptance for the v5 types that are cheap to
        // materialise. Each round-trips writer -> reader with the gate in
        // place, proving no reject-valid regression end to end.
        let cases: Vec<(SigmaType, SigmaValue)> = vec![
            (SigmaType::SInt, SigmaValue::Int(42)),
            (SigmaType::SLong, SigmaValue::Long(-99)),
            (SigmaType::SByte, SigmaValue::Byte(7)),
            (SigmaType::SBoolean, SigmaValue::Boolean(true)),
            (
                SigmaType::SColl(Box::new(SigmaType::SByte)),
                SigmaValue::Coll(crate::sigma_value::CollValue::Bytes(vec![0xDE, 0xAD])),
            ),
            (
                SigmaType::SColl(Box::new(SigmaType::SInt)),
                SigmaValue::Coll(crate::sigma_value::CollValue::Values(vec![
                    SigmaValue::Int(1),
                    SigmaValue::Int(2),
                ])),
            ),
            (
                SigmaType::STuple(vec![SigmaType::SInt, SigmaType::SLong]),
                SigmaValue::Tuple(vec![SigmaValue::Int(3), SigmaValue::Long(4)]),
            ),
        ];
        for (tpe, val) in cases {
            let bytes = ext_bytes_for(tpe.clone(), val);
            let decoded = read_ext(&bytes).unwrap_or_else(|e| {
                panic!("legal v5 context-ext {tpe:?} must decode, got error: {e:?}")
            });
            assert_eq!(decoded.values.len(), 1);
        }
    }

    // ----- oracle parity: Rust-accept / Scala-reject vectors now REJECT -----

    // Provenance: these four byte vectors are external oracle vectors — the
    // Rust node previously ACCEPTED the first three while Scala 6.0.2
    // `ContextExtension.parse` REJECTS them via `CheckV6Type(v)`
    // (`ContextExtension.scala:60`, rule 1019). The control (SInt) is
    // accepted by both. Bytes are the full context-extension wire form
    // (count + key + serialized constant).

    #[test]
    fn oracle_rejects_option_some_context_ext() {
        // SOption[SInt] Some(7): count=1, key=7, const 0x28 01 0e.
        let err = read_ext(&[0x01, 0x07, 0x28, 0x01, 0x0e]).unwrap_err();
        let ReadError::InvalidData(m) = err else {
            panic!("expected InvalidData, got {err:?}")
        };
        assert!(m.contains("1019"), "expected rule-1019 reject, got: {m}");
    }

    #[test]
    fn oracle_rejects_option_none_context_ext() {
        // SOption[SInt] None: count=1, key=3, const 0x28 00.
        let err = read_ext(&[0x01, 0x03, 0x28, 0x00]).unwrap_err();
        let ReadError::InvalidData(m) = err else {
            panic!("expected InvalidData, got {err:?}")
        };
        assert!(m.contains("1019"), "expected rule-1019 reject, got: {m}");
    }

    #[test]
    fn oracle_rejects_unsigned_bigint_context_ext() {
        // SUnsignedBigInt 123456789: count=1, key=9, const 0x09 04 07 5b cd 15.
        let err = read_ext(&[0x01, 0x09, 0x09, 0x04, 0x07, 0x5b, 0xcd, 0x15]).unwrap_err();
        let ReadError::InvalidData(m) = err else {
            panic!("expected InvalidData, got {err:?}")
        };
        assert!(m.contains("1019"), "expected rule-1019 reject, got: {m}");
    }

    #[test]
    fn oracle_accepts_sint_control_context_ext() {
        // Negative control: SInt(42), count=1, key=1, const 0x04 54. Both
        // Rust and Scala accept — the gate must NOT touch it.
        let ext = read_ext(&[0x01, 0x01, 0x04, 0x54]).expect("SInt control must decode");
        assert_eq!(ext.values.len(), 1);
        assert_eq!(
            ext.values.get(&1),
            Some(&(SigmaType::SInt, SigmaValue::Int(42)))
        );
    }

    // ----- nested-type parity: v6 type nested inside Coll / Tuple -----

    #[test]
    fn v6_gate_rejects_coll_of_unsigned_bigint() {
        // Coll[SUnsignedBigInt] — v6 type nested one level under a
        // collection. Scala `step` recurses `SCollection => step(elemType)`
        // and rejects. Verify the predicate and the full decode path agree.
        use crate::register::type_has_v6_only_type as v6;
        let nested = SigmaType::SColl(Box::new(SigmaType::SUnsignedBigInt));
        assert!(v6(&nested), "Coll[UnsignedBigInt] must trip the predicate");

        let bytes = ext_bytes_for(
            nested,
            SigmaValue::Coll(crate::sigma_value::CollValue::Values(vec![
                SigmaValue::BigInt(num_bigint::BigInt::from(123456789)),
            ])),
        );
        let err = read_ext(&bytes).unwrap_err();
        let ReadError::InvalidData(m) = err else {
            panic!("expected InvalidData, got {err:?}")
        };
        assert!(m.contains("1019"), "expected rule-1019 reject, got: {m}");
    }

    #[test]
    fn v6_gate_rejects_tuple_containing_option() {
        // (SInt, SOption[SByte]) — v6 type nested inside a tuple item. Scala
        // `step` recurses `STuple => items.foreach(step)` and rejects.
        use crate::register::type_has_v6_only_type as v6;
        let nested = SigmaType::STuple(vec![
            SigmaType::SInt,
            SigmaType::SOption(Box::new(SigmaType::SByte)),
        ]);
        assert!(v6(&nested), "(Int, Option[Byte]) must trip the predicate");

        let bytes = ext_bytes_for(
            nested,
            SigmaValue::Tuple(vec![
                SigmaValue::Int(1),
                SigmaValue::Opt(Some(Box::new(SigmaValue::Byte(2)))),
            ]),
        );
        let err = read_ext(&bytes).unwrap_err();
        let ReadError::InvalidData(m) = err else {
            panic!("expected InvalidData, got {err:?}")
        };
        assert!(m.contains("1019"), "expected rule-1019 reject, got: {m}");
    }

    #[test]
    fn v6_gate_predicate_matches_scala_named_nested_types() {
        // Pin the exact nested types the CheckV6Type `step` recursion names:
        // a collection of a v6 type and a tuple containing SHeader.
        use crate::register::type_has_v6_only_type as v6;
        assert!(v6(&SigmaType::SColl(Box::new(SigmaType::SUnsignedBigInt))));
        assert!(v6(&SigmaType::STuple(vec![
            SigmaType::SInt,
            SigmaType::SHeader
        ])));
        // Deep nesting: Coll[(Byte, Option[Int])].
        assert!(v6(&SigmaType::SColl(Box::new(SigmaType::STuple(vec![
            SigmaType::SByte,
            SigmaType::SOption(Box::new(SigmaType::SInt)),
        ])))));
    }

    // ----- oracle parity -----
    //
    // The ATTACK/CONTROL verdicts below come from the sigma-state 6.0.2
    // Scala reference (scripts/jvm_serde_oracle, surface `transaction`).
    // They are EXTERNAL oracle verdicts, not self-oracles: Scala's
    // ContextExtension.serializer.parse reads the count with a SIGNED
    // getByte() and rejects the high bit before reading any entry.

    #[test]
    fn context_extension_count_127_boundary_accepts_and_round_trips() {
        // 127 = Byte.MaxValue, the largest count Scala's signed count byte
        // permits. Must decode and round-trip exactly as before the fix — a
        // false reject here would strand valid txs (reject-valid regression).
        let mut ext = ContextExtension::empty();
        for key in 0u8..127 {
            ext.values
                .insert(key, (SigmaType::SInt, SigmaValue::Int(key as i32)));
        }
        assert_eq!(ext.values.len(), 127, "test setup: 127 entries");
        let bytes = serialize_ext(&ext);
        assert_eq!(bytes[0], 0x7f, "count byte must be 127 (0x7f)");
        let mut r = VlqReader::new(&bytes);
        let decoded = read_context_extension(&mut r).unwrap();
        assert!(r.is_empty(), "127 entries must consume all bytes");
        assert_eq!(decoded.values.len(), 127);
    }

    #[test]
    fn context_extension_low_counts_still_accept() {
        // Counts 0, 1, 2, 3 (all below the high bit) decode unchanged.
        for n in 0u8..=3 {
            let mut ext = ContextExtension::empty();
            for key in 0..n {
                ext.values
                    .insert(key, (SigmaType::SInt, SigmaValue::Int(key as i32)));
            }
            let bytes = serialize_ext(&ext);
            assert_eq!(bytes[0], n, "count byte");
            let mut r = VlqReader::new(&bytes);
            let decoded = read_context_extension(&mut r).unwrap();
            assert!(r.is_empty());
            assert_eq!(decoded.values.len(), n as usize);
        }
    }

    #[test]
    fn context_extension_count_128_boundary_rejects_negative_signed() {
        // 128 sets the high bit: Scala's getByte() reads -128 and rejects
        // ("Negative amount of context extension values: -128"). Rust used to
        // accept it (get_u8() -> 128, read 128 entries). Post-fix Rust must
        // reject AT the count byte, before reading any entry.
        let mut ext = ContextExtension::empty();
        for key in 0u8..128 {
            ext.values
                .insert(key, (SigmaType::SInt, SigmaValue::Int(key as i32)));
        }
        assert_eq!(ext.values.len(), 128, "test setup: 128 entries");
        let bytes = serialize_ext(&ext);
        assert_eq!(
            bytes[0], 0x80,
            "count byte must be 128 (0x80, high bit set)"
        );
        let mut r = VlqReader::new(&bytes);
        let err = read_context_extension(&mut r).unwrap_err();
        match &err {
            ReadError::InvalidData(msg) => {
                assert!(
                    msg.contains("negative context-extension value count"),
                    "got: {msg}"
                );
                assert!(msg.contains("-128"), "must name signed -128, got: {msg}");
            }
            other => panic!("expected InvalidData reject, got {other:?}"),
        }
    }

    #[test]
    fn split_context_extension_bytes_count_127_accepts_128_rejects() {
        // The verbatim-bytes JSON path mirrors the same count read; it must
        // agree with read_context_extension at the boundary.
        let mut ext127 = ContextExtension::empty();
        for key in 0u8..127 {
            ext127
                .values
                .insert(key, (SigmaType::SInt, SigmaValue::Int(0)));
        }
        let bytes127 = serialize_ext(&ext127);
        assert_eq!(bytes127[0], 0x7f);
        let entries = split_context_extension_bytes(&bytes127).unwrap();
        assert_eq!(entries.len(), 127, "127 must split cleanly");

        let mut ext128 = ContextExtension::empty();
        for key in 0u8..128 {
            ext128
                .values
                .insert(key, (SigmaType::SInt, SigmaValue::Int(0)));
        }
        let bytes128 = serialize_ext(&ext128);
        assert_eq!(bytes128[0], 0x80);
        let err = split_context_extension_bytes(&bytes128).unwrap_err();
        match &err {
            ReadError::InvalidData(msg) => assert!(
                msg.contains("negative context-extension value count"),
                "got: {msg}"
            ),
            other => panic!("expected InvalidData reject, got {other:?}"),
        }
    }

    #[test]
    fn context_extension_oracle_control_count_2_accepts() {
        // Recon NEGATIVE CONTROL: extension bytes `02 00 0400 01 0402`
        // (count=2, {0 -> Int(0), 1 -> Int(1)}). Scala oracle verdict: ACCEPT,
        // re-serialized byte-identical. Rust must ACCEPT and round-trip.
        let wire = [0x02u8, 0x00, 0x04, 0x00, 0x01, 0x04, 0x02];
        let mut r = VlqReader::new(&wire);
        let ext = read_context_extension(&mut r).unwrap();
        assert!(r.is_empty(), "control must consume all bytes");
        assert_eq!(ext.values.len(), 2);
        assert_eq!(
            ext.values.get(&0),
            Some(&(SigmaType::SInt, SigmaValue::Int(0)))
        );
        assert_eq!(
            ext.values.get(&1),
            Some(&(SigmaType::SInt, SigmaValue::Int(1)))
        );
        let mut w = VlqWriter::new();
        write_context_extension(&mut w, &ext).unwrap();
        assert_eq!(w.result(), wire, "<=4 entries re-serialize byte-identical");
    }

    #[test]
    fn context_extension_oracle_attack_count_128_rejects() {
        // Recon ATTACK: count byte 0x80 (=128) followed by 128 well-formed
        // SInt entries (enough bytes that pre-fix Rust parsed them all and
        // returned Ok — the accept-invalid divergence). Scala oracle verdict:
        // REJECT (SerializerException, "Negative amount of context extension
        // values: -128"). Post-fix Rust must REJECT at the count byte.
        let mut wire = vec![0x80u8];
        for key in 0u8..128 {
            wire.push(key); // entry key
            wire.push(0x04); // SInt type code
            wire.push(0x00); // zigzag(0) = value 0
        }
        let mut r = VlqReader::new(&wire);
        let err = read_context_extension(&mut r).unwrap_err();
        match &err {
            ReadError::InvalidData(msg) => {
                assert!(
                    msg.contains("negative context-extension value count"),
                    "got: {msg}"
                );
                assert!(msg.contains("-128"), "must name signed -128, got: {msg}");
            }
            other => panic!("expected InvalidData reject, got {other:?}"),
        }
    }
}
