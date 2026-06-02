//! `IndexedToken` parent record. Mirrors Scala `IndexedToken.scala`.
//!
//! Token records are keyed by
//! `unique_id(tokenId) = blake2b256(utf8(token_id_hex) ‖ utf8("token"))`
//! (see [`crate::segment_id::token_unique_id`]). Like
//! `IndexedContractTemplate`, a token record carries no `BalanceInfo`
//! and only a box-segment (no tx-segment).
//!
//! Wire layout:
//! ```text
//! [tokenId:        32 bytes raw]
//! [creatingBoxId:  Opt<32 bytes raw>]
//! [emissionAmount: Opt<u64 unsigned VLQ — putULong, NOT zigzag>]
//! [name:           Opt<u16 len + UTF-8 bytes>]
//! [description:    Opt<u16 len + UTF-8 bytes>]
//! [decimals:       Opt<i32 zigzag VLQ — putInt>]
//! [segment body]                              // see `crate::segment`
//! ```
//!
//! The `u64` vs `i32` distinction is load-bearing: swapping `putULong`
//! with `putInt` (zigzag) silently corrupts both fields for any value
//! ≥ 64 (where unsigned VLQ and zigzag-encoded positives differ in the
//! leading bytes).
//!
//! Mint detection: see [`is_mint`]. The IndexedToken record is
//! constructed via [`IndexedToken::from_box`] on first detection and
//! mutated via [`IndexedToken::add_emission_amount`] on each subsequent
//! same-tx detection (multi-output mint).

use std::collections::{HashMap, HashSet};

use ergo_primitives::reader::{ReadError, VlqReader};
use ergo_primitives::writer::VlqWriter;
use ergo_ser::register::{AdditionalRegisters, RegisterId, RegisterValue};
use ergo_ser::sigma_value::{CollValue, SigmaValue};
use ergo_ser::token::Token;
use redb::{ReadableTable, Table};

use ergo_indexer_types::{BoxId, TokenId};

use crate::error::IndexerError;
use crate::segment::{read_segment, write_segment, Segment};
use crate::segment_id::token_unique_id;

/// Parent record under `INDEXED_TOKEN`, keyed by
/// `token_unique_id(token_id)`.
///
/// `token_id` is the raw token id (NOT the unique id); the unique id is
/// derived only when reading/writing the redb key. Storing the raw
/// token id lets `from_box` callers and external consumers reconstruct
/// the unique id without re-deriving from a separate field.
///
/// All five `Option` fields are pinned to `Some(_)` for records
/// constructed via [`IndexedToken::from_box`] — even the empty-string
/// defaults for missing R4/R5 and the zero default for missing R6.
/// The `Option` shape exists for wire-format symmetry with
/// Scala's `Opt[X]` putOption encoding (`Some("")` ≠ `None` byte-wise),
/// not because well-formed records ever carry `None` here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexedToken {
    pub token_id: TokenId,
    pub creating_box_id: Option<BoxId>,
    pub emission_amount: Option<u64>,
    pub name: Option<String>,
    pub description: Option<String>,
    pub decimals: Option<i32>,
    /// Box-segment for this token. The `txs` field is unused for
    /// tokens (Scala tracks only boxes here, like templates) and
    /// apply paths must keep it empty; the wire format still permits
    /// non-empty `txs` for symmetry with the shared `Segment` shape.
    pub segment: Segment,
}

impl IndexedToken {
    /// New empty parent record — every `Option` field is `None` and
    /// the segment is empty. Use this only as a placeholder before
    /// [`IndexedToken::from_box`] populates the metadata. Apply paths
    /// must never persist a record in this state.
    pub fn empty(token_id: TokenId) -> Self {
        Self {
            token_id,
            creating_box_id: None,
            emission_amount: None,
            name: None,
            description: None,
            decimals: None,
            segment: Segment::empty(),
        }
    }

    /// Construct a freshly-minted IndexedToken from the emission box.
    /// Mirrors Scala `IndexedToken.fromBox(iEb, j)`
    /// (`IndexedToken.scala:179-218`):
    /// - `creating_box_id` = the output box's id (the box that owns
    ///   `additionalTokens(j)`).
    /// - `emission_amount` = the `j`-th token's amount on that box.
    /// - `name`, `description`, `decimals` decoded from R4/R5/R6;
    ///   missing/wrong-type registers default to `Some("")` /
    ///   `Some("")` / `Some(0)` (NOT `None` — preserves wire-byte
    ///   parity with Scala's pinned defaults).
    pub fn from_box(box_id: &BoxId, token: &Token, regs: &AdditionalRegisters) -> Self {
        Self {
            token_id: token.token_id,
            creating_box_id: Some(*box_id),
            emission_amount: Some(token.amount),
            name: Some(decode_name_r4(regs)),
            description: Some(decode_description_r5(regs)),
            decimals: Some(decode_decimals_r6(regs)),
            segment: Segment::empty(),
        }
    }

    /// Add to the running emission total. Called on second-and-later
    /// mint detections of the same `token_id` within a single tx
    /// (multi-output mint, `ExtraIndexer.scala:355-357`). When the
    /// existing `emission_amount` is `None` (only possible for an
    /// `empty` placeholder), treat it as `0` so the result is just
    /// `Some(amount)` — Scala's `Long += amount` from a freshly
    /// initialized `0L` produces the same value.
    ///
    /// Saturates on overflow rather than wrapping. Scala's signed
    /// `Long += amount` would wrap silently to negative; our wire
    /// format is unsigned `u64` so wrapping wouldn't even round-trip.
    /// Realistic token emissions are nowhere near `u64::MAX`, so the
    /// saturation branch should never fire in practice.
    pub fn add_emission_amount(&mut self, amount: u64) {
        let current = self.emission_amount.unwrap_or(0);
        self.emission_amount = Some(current.saturating_add(amount));
    }
}

/// Serialize an `IndexedToken` parent record. Layout matches
/// `IndexedTokenSerializer.serialize` (`IndexedToken.scala:129-145`).
pub fn write_indexed_token(w: &mut VlqWriter, t: &IndexedToken) {
    w.put_bytes(t.token_id.as_bytes());
    write_option_box_id(w, t.creating_box_id.as_ref());
    write_option_emission_amount(w, t.emission_amount);
    write_option_string(w, t.name.as_deref());
    write_option_string(w, t.description.as_deref());
    write_option_decimals(w, t.decimals);
    write_segment(w, &t.segment);
}

/// Parse an `IndexedToken` parent record. Inverse of
/// [`write_indexed_token`].
pub fn read_indexed_token(r: &mut VlqReader) -> Result<IndexedToken, ReadError> {
    let id_bytes = r.get_bytes(32)?;
    let mut id_arr = [0u8; 32];
    id_arr.copy_from_slice(id_bytes);
    let token_id = TokenId::from_bytes(id_arr);
    let creating_box_id = read_option_box_id(r)?;
    let emission_amount = read_option_emission_amount(r)?;
    let name = read_option_string(r)?;
    let description = read_option_string(r)?;
    let decimals = read_option_decimals(r)?;
    let segment = read_segment(r)?;
    Ok(IndexedToken {
        token_id,
        creating_box_id,
        emission_amount,
        name,
        description,
        decimals,
        segment,
    })
}

/// EIP-4 mint predicate. Mirrors `ExtraIndexer.scala:351-358`:
/// `tokenId == tx.inputs.head.boxId && tokenId ∉ inputTokens`.
///
/// `first_input_box_id` is `tx.inputs[0].box_id`. Genesis (`height == 1`)
/// txs still have inputs (the implicit genesis box id) so this is
/// always defined; the genesis special-case is *only* the skip of
/// step-1 input processing in the apply loop, not the mint check.
pub(crate) fn is_mint(
    token_id: &TokenId,
    first_input_box_id: &BoxId,
    input_tokens: &HashSet<TokenId>,
) -> bool {
    token_id.as_bytes() == first_input_box_id.as_bytes() && !input_tokens.contains(token_id)
}

/// Lazy-load helper for the mint detection path. On first touch of
/// `token_id` in this block, read the persisted record (or build an
/// empty placeholder if absent) and stash it in `map`. Returns a
/// mutable reference for in-place mutation.
///
/// Empty placeholders (`creating_box_id == None`) only occur via the
/// "DB miss + caller is about to fill in mint metadata" path. The
/// caller must immediately replace the record with a `from_box`-style
/// initialization or call `add_emission_amount` so the placeholder is
/// never persisted in that state. `flush_tokens` defensively skips
/// any placeholder that escaped that contract.
pub(crate) fn load_token_into_map<'a>(
    token_table: &Table<&[u8], &[u8]>,
    map: &'a mut HashMap<TokenId, IndexedToken>,
    token_id: TokenId,
) -> Result<&'a mut IndexedToken, IndexerError> {
    use std::collections::hash_map::Entry;
    match map.entry(token_id) {
        Entry::Occupied(e) => Ok(e.into_mut()),
        Entry::Vacant(e) => {
            let key = token_unique_id(&token_id);
            let loaded = match token_table.get(key.as_bytes().as_slice())? {
                Some(g) => {
                    let mut r = VlqReader::new(g.value());
                    let parsed =
                        read_indexed_token(&mut r).map_err(|source| IndexerError::DbDecode {
                            context: "indexed_token",
                            source,
                        })?;
                    if !r.is_empty() {
                        return Err(IndexerError::DbRowLength {
                            context: "indexed_token",
                            expected: r.position(),
                            got: g.value().len(),
                        });
                    }
                    parsed
                }
                None => IndexedToken::empty(token_id),
            };
            Ok(e.insert(loaded))
        }
    }
}

/// Lookup-only helper for the non-mint segment-append path. Does NOT
/// create an empty placeholder on miss — returns `Ok(None)` so the
/// caller can skip the segment append for tokens that have no
/// IndexedToken record. `[derived]` defensive: mainnet invariant says
/// the record exists for every chain-validated token (every token
/// originates from an EIP-4 mint that creates the record), but
/// preserving the skip path keeps the indexer from synthesizing
/// placeholders that Scala's `findAndUpdateToken` would have dropped.
pub(crate) fn try_load_token_into_map<'a>(
    token_table: &Table<&[u8], &[u8]>,
    map: &'a mut HashMap<TokenId, IndexedToken>,
    token_id: TokenId,
) -> Result<Option<&'a mut IndexedToken>, IndexerError> {
    use std::collections::hash_map::Entry;
    match map.entry(token_id) {
        Entry::Occupied(e) => Ok(Some(e.into_mut())),
        Entry::Vacant(e) => {
            let key = token_unique_id(&token_id);
            let Some(g) = token_table.get(key.as_bytes().as_slice())? else {
                return Ok(None);
            };
            let mut r = VlqReader::new(g.value());
            let loaded = read_indexed_token(&mut r).map_err(|source| IndexerError::DbDecode {
                context: "indexed_token",
                source,
            })?;
            if !r.is_empty() {
                return Err(IndexerError::DbRowLength {
                    context: "indexed_token",
                    expected: r.position(),
                    got: g.value().len(),
                });
            }
            Ok(Some(e.insert(loaded)))
        }
    }
}

/// Flush every touched IndexedToken back to `INDEXED_TOKEN`. Records
/// listed in `to_remove` are deleted from the table instead of
/// written (used by rollback to drop tokens whose mint was reversed).
/// Records that escaped the load-then-fill contract with
/// `creating_box_id == None` AND empty segment are skipped — they
/// represent placeholders no mutation touched.
///
/// `writer` is cleared before every row via `write_then_insert`, so a
/// caller passing a long-lived shared writer cannot leak bytes from a
/// prior emit into the first row, and an early `?` from any row cannot
/// leak into the next.
pub(crate) fn flush_tokens(
    token_table: &mut Table<&[u8], &[u8]>,
    writer: &mut VlqWriter,
    map: &HashMap<TokenId, IndexedToken>,
    to_remove: &HashSet<TokenId>,
) -> Result<(), IndexerError> {
    for (token_id, t) in map {
        if to_remove.contains(token_id) {
            continue;
        }
        if t.creating_box_id.is_none()
            && t.segment.boxes.is_empty()
            && t.segment.box_segment_count == 0
        {
            continue;
        }
        let key = token_unique_id(token_id);
        crate::apply::write_then_insert(token_table, writer, key.as_bytes().as_slice(), |w| {
            write_indexed_token(w, t);
            Ok(())
        })?;
    }
    for token_id in to_remove {
        let key = token_unique_id(token_id);
        token_table.remove(key.as_bytes().as_slice())?;
    }
    Ok(())
}

// ---- Register decoders ----

/// Decode R4 as a UTF-8 name. Default `""` on missing or wrong type.
/// Mirrors `IndexedToken.scala:184` — `new String(bytes, "UTF-8")` with
/// the JVM default replace-malformed action (U+FFFD), which Rust's
/// `String::from_utf8_lossy` matches.
pub(crate) fn decode_name_r4(regs: &AdditionalRegisters) -> String {
    decode_string_register(regs, RegisterId::R4)
}

/// Decode R5 as a UTF-8 description. Default `""` on missing or wrong
/// type. Mirrors `IndexedToken.scala:195`.
pub(crate) fn decode_description_r5(regs: &AdditionalRegisters) -> String {
    decode_string_register(regs, RegisterId::R5)
}

fn decode_string_register(regs: &AdditionalRegisters, id: RegisterId) -> String {
    match regs.get(id) {
        Some(RegisterValue {
            value: SigmaValue::Coll(CollValue::Bytes(bytes)),
            ..
        }) => String::from_utf8_lossy(bytes).into_owned(),
        _ => String::new(),
    }
}

/// Decode R6 as decimals. Branch order is load-bearing (`IndexedToken.scala:203-217`):
///
/// 1. **Primary**: if R6 is `Coll[Byte]`, decode the bytes as UTF-8
///    ASCII decimal and parse as `i32`. Fall through on type mismatch
///    or parse failure (NOT to 0).
/// 2. **First fallback**: if R6 is `SInt`, return the int directly.
///    Fall through on type mismatch.
/// 3. **Default**: `0`. Also taken when R6 is absent.
///
/// Short-circuiting to 0 on first failure (e.g. only handling the
/// bytes-decimal branch) loses tokens that mint with `SInt` decimals.
pub(crate) fn decode_decimals_r6(regs: &AdditionalRegisters) -> i32 {
    let Some(reg) = regs.get(RegisterId::R6) else {
        return 0;
    };
    if let SigmaValue::Coll(CollValue::Bytes(bytes)) = &reg.value {
        if let Ok(s) = std::str::from_utf8(bytes) {
            if let Ok(n) = s.parse::<i32>() {
                return n;
            }
        }
    }
    if let SigmaValue::Int(i) = reg.value {
        return i;
    }
    0
}

// ---- Option<X> wire-format helpers (Scorex putOption pattern) ----
//
// Each `Opt[X]` is `[0x01, X bytes...]` if Some, `[0x00]` if None.
// Mirrors Scala's `Writer.putOption` (single byte boolean marker +
// optional inner content).

fn write_option_box_id(w: &mut VlqWriter, b: Option<&BoxId>) {
    match b {
        Some(id) => {
            w.put_u8(0x01);
            w.put_bytes(id.as_bytes());
        }
        None => w.put_u8(0x00),
    }
}

fn read_option_box_id(r: &mut VlqReader) -> Result<Option<BoxId>, ReadError> {
    let flag = r.get_u8()?;
    match flag {
        0x00 => Ok(None),
        0x01 => {
            let bytes = r.get_bytes(32)?;
            let mut arr = [0u8; 32];
            arr.copy_from_slice(bytes);
            Ok(Some(BoxId::from_bytes(arr)))
        }
        other => Err(ReadError::InvalidData(format!(
            "IndexedToken creating_box_id Option flag must be 0x00 or 0x01, got 0x{other:02x}"
        ))),
    }
}

fn write_option_emission_amount(w: &mut VlqWriter, v: Option<u64>) {
    match v {
        Some(amount) => {
            w.put_u8(0x01);
            w.put_u64(amount);
        }
        None => w.put_u8(0x00),
    }
}

fn read_option_emission_amount(r: &mut VlqReader) -> Result<Option<u64>, ReadError> {
    let flag = r.get_u8()?;
    match flag {
        0x00 => Ok(None),
        0x01 => Ok(Some(r.get_u64()?)),
        other => Err(ReadError::InvalidData(format!(
            "IndexedToken emission_amount Option flag must be 0x00 or 0x01, got 0x{other:02x}"
        ))),
    }
}

fn write_option_string(w: &mut VlqWriter, s: Option<&str>) {
    match s {
        Some(text) => {
            w.put_u8(0x01);
            let bytes = text.as_bytes();
            // Scala writes name/description length as `putUShort` —
            // Scorex range-checks `[0, 65535]` then encodes via VLQ.
            let len_u16 = u16::try_from(bytes.len()).unwrap_or(u16::MAX);
            w.put_u16(len_u16);
            w.put_bytes(&bytes[..len_u16 as usize]);
        }
        None => w.put_u8(0x00),
    }
}

fn read_option_string(r: &mut VlqReader) -> Result<Option<String>, ReadError> {
    let flag = r.get_u8()?;
    match flag {
        0x00 => Ok(None),
        0x01 => {
            let len = r.get_u16()? as usize;
            let bytes = r.get_bytes(len)?;
            Ok(Some(String::from_utf8_lossy(bytes).into_owned()))
        }
        other => Err(ReadError::InvalidData(format!(
            "IndexedToken string Option flag must be 0x00 or 0x01, got 0x{other:02x}"
        ))),
    }
}

fn write_option_decimals(w: &mut VlqWriter, v: Option<i32>) {
    match v {
        Some(n) => {
            w.put_u8(0x01);
            w.put_i32(n);
        }
        None => w.put_u8(0x00),
    }
}

fn read_option_decimals(r: &mut VlqReader) -> Result<Option<i32>, ReadError> {
    let flag = r.get_u8()?;
    match flag {
        0x00 => Ok(None),
        0x01 => Ok(Some(r.get_i32()?)),
        other => Err(ReadError::InvalidData(format!(
            "IndexedToken decimals Option flag must be 0x00 or 0x01, got 0x{other:02x}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_primitives::digest::Digest32;
    use ergo_ser::sigma_type::SigmaType;

    // ----- helpers -----

    fn d(hex_str: &str) -> Digest32 {
        let bytes = hex::decode(hex_str).expect("valid hex");
        let arr: [u8; 32] = bytes.try_into().expect("32 bytes");
        Digest32::from_bytes(arr)
    }

    fn roundtrip(t: &IndexedToken) -> Vec<u8> {
        let mut w = VlqWriter::new();
        write_indexed_token(&mut w, t);
        let bytes = w.result();
        let mut r = VlqReader::new(&bytes);
        let parsed = read_indexed_token(&mut r).unwrap();
        assert!(r.is_empty(), "leftover bytes after IndexedToken roundtrip");
        assert_eq!(&parsed, t);
        bytes
    }

    fn regs_with(entries: Vec<(SigmaType, SigmaValue)>) -> AdditionalRegisters {
        AdditionalRegisters {
            registers: entries
                .into_iter()
                .map(|(tpe, value)| RegisterValue { tpe, value })
                .collect(),
        }
    }

    // ----- round-trips -----

    #[test]
    fn empty_token_all_options_none_roundtrips() {
        let t = IndexedToken::empty(TokenId::ZERO);
        let bytes = roundtrip(&t);
        // 32B token_id + 5 × 1B None flag + 4B empty Segment = 41B
        assert_eq!(bytes.len(), 32 + 5 + 4);
        // Every Option flag must be 0x00 (None).
        for (offset, b) in bytes.iter().enumerate().take(37).skip(32) {
            assert_eq!(*b, 0x00, "Option flag at offset {offset}");
        }
    }

    #[test]
    fn token_with_full_metadata_roundtrips() {
        let t = IndexedToken {
            token_id: d("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            creating_box_id: Some(d(
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            )),
            emission_amount: Some(1_000_000_000_000_u64),
            name: Some("ErgoToken".to_string()),
            description: Some("A short description".to_string()),
            decimals: Some(9),
            segment: Segment {
                txs: vec![],
                boxes: vec![10, -20, 30],
                box_segment_count: 0,
                tx_segment_count: 0,
            },
        };
        roundtrip(&t);
    }

    #[test]
    fn token_with_some_empty_strings_roundtrips() {
        // Defaults from from_box are `Some("")`, NOT `None`. The wire
        // bytes for `Some("")` are `[0x01, 0x00]` (flag + len=0); for
        // `None` they are `[0x00]`. Both must roundtrip.
        let t = IndexedToken {
            token_id: TokenId::ZERO,
            creating_box_id: Some(d(
                "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            )),
            emission_amount: Some(0),
            name: Some(String::new()),
            description: Some(String::new()),
            decimals: Some(0),
            segment: Segment::empty(),
        };
        roundtrip(&t);
    }

    #[test]
    fn token_with_partial_metadata_roundtrips() {
        let t = IndexedToken {
            token_id: d("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
            creating_box_id: Some(d(
                "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
            )),
            emission_amount: Some(42),
            name: None,
            description: Some("only desc".to_string()),
            decimals: None,
            segment: Segment::empty(),
        };
        roundtrip(&t);
    }

    #[test]
    fn token_with_box_spill_count_roundtrips() {
        let t = IndexedToken {
            token_id: TokenId::ZERO,
            creating_box_id: None,
            emission_amount: None,
            name: None,
            description: None,
            decimals: None,
            segment: Segment {
                txs: vec![],
                boxes: (0..100i64).collect(),
                box_segment_count: 3,
                tx_segment_count: 0,
            },
        };
        roundtrip(&t);
    }

    #[test]
    fn token_starts_with_id_then_options_then_segment() {
        // Defensive: confirm the wire layout starts with the 32-byte
        // raw token_id, NOT a length prefix or option flag.
        let t = IndexedToken::empty(TokenId::from_bytes([0xCC; 32]));
        let mut w = VlqWriter::new();
        write_indexed_token(&mut w, &t);
        let bytes = w.result();
        assert_eq!(&bytes[..32], &[0xCC; 32], "token_id prefix");
        // First Option (creating_box_id) flag at offset 32.
        assert_eq!(bytes[32], 0x00, "creating_box_id None flag");
    }

    #[test]
    fn emission_amount_uses_unsigned_vlq_not_zigzag() {
        // Value 64 decodes differently under unsigned-VLQ (1 byte:
        // 0x40) vs zigzag (2 bytes: 0x80, 0x01). Locking the unsigned
        // path catches a regression where putULong is swapped with
        // putInt — pinned by the unsigned-VLQ wire-format invariant.
        let t = IndexedToken {
            token_id: TokenId::ZERO,
            creating_box_id: None,
            emission_amount: Some(64),
            name: None,
            description: None,
            decimals: None,
            segment: Segment::empty(),
        };
        let mut w = VlqWriter::new();
        write_indexed_token(&mut w, &t);
        let bytes = w.result();
        // Layout: 32B token_id, 1B None flag for creating_box_id,
        // 1B Some flag for emission_amount, then VLQ-encoded 64.
        let amount_flag_offset = 32 + 1;
        assert_eq!(bytes[amount_flag_offset], 0x01);
        // Unsigned VLQ for 64 is one byte 0x40. Zigzag VLQ for +64 is
        // two bytes 0x80 0x01 — assert single-byte 0x40 to lock the
        // unsigned-VLQ wire encoding.
        assert_eq!(bytes[amount_flag_offset + 1], 0x40);
        // Next byte must be the next field's Option flag, NOT a VLQ
        // continuation byte.
        assert_eq!(bytes[amount_flag_offset + 2], 0x00, "name None flag");
    }

    #[test]
    fn decimals_uses_zigzag_vlq_for_negative_values() {
        // i32 -1 zigzags to 1 (wire 0x01); +1 zigzags to 2 (wire 0x02).
        // Round-trip both negative and positive to lock the signed-zigzag
        // path on `decimals`.
        for value in [-1i32, 1, -100, 100] {
            let t = IndexedToken {
                token_id: TokenId::ZERO,
                creating_box_id: None,
                emission_amount: None,
                name: None,
                description: None,
                decimals: Some(value),
                segment: Segment::empty(),
            };
            roundtrip(&t);
        }
    }

    #[test]
    fn invalid_option_flag_rejected() {
        // 32B token_id + 0x77 garbage flag for creating_box_id.
        let mut bytes = vec![0u8; 32];
        bytes.push(0x77);
        let mut r = VlqReader::new(&bytes);
        let err = read_indexed_token(&mut r).unwrap_err();
        match err {
            ReadError::InvalidData(msg) => assert!(msg.contains("0x77")),
            other => panic!("expected InvalidData, got {other:?}"),
        }
    }

    // ---- Register decoder tests ----

    #[test]
    fn decode_name_returns_empty_when_r4_missing() {
        let regs = AdditionalRegisters::empty();
        assert_eq!(decode_name_r4(&regs), "");
    }

    #[test]
    fn decode_name_returns_empty_when_r4_wrong_type() {
        // R4 holds an SInt instead of Coll[Byte] — Scala throws
        // ClassCastException; we default to "".
        let regs = regs_with(vec![(SigmaType::SInt, SigmaValue::Int(42))]);
        assert_eq!(decode_name_r4(&regs), "");
    }

    #[test]
    fn decode_name_decodes_utf8_byte_coll() {
        let regs = regs_with(vec![(
            SigmaType::SColl(Box::new(SigmaType::SByte)),
            SigmaValue::Coll(CollValue::Bytes("ErgoToken".as_bytes().to_vec())),
        )]);
        assert_eq!(decode_name_r4(&regs), "ErgoToken");
    }

    #[test]
    fn decode_description_returns_empty_when_r5_missing() {
        let regs = regs_with(vec![(
            SigmaType::SColl(Box::new(SigmaType::SByte)),
            SigmaValue::Coll(CollValue::Bytes(b"name".to_vec())),
        )]);
        // R4 is present but R5 isn't.
        assert_eq!(decode_description_r5(&regs), "");
    }

    #[test]
    fn decode_decimals_returns_zero_when_r6_missing() {
        let regs = AdditionalRegisters::empty();
        assert_eq!(decode_decimals_r6(&regs), 0);
    }

    #[test]
    fn decode_decimals_parses_byte_coll_as_ascii_decimal() {
        // R4, R5 placeholders + R6 = Coll[Byte] holding ASCII "9".
        let regs = regs_with(vec![
            (
                SigmaType::SColl(Box::new(SigmaType::SByte)),
                SigmaValue::Coll(CollValue::Bytes(b"name".to_vec())),
            ),
            (
                SigmaType::SColl(Box::new(SigmaType::SByte)),
                SigmaValue::Coll(CollValue::Bytes(b"desc".to_vec())),
            ),
            (
                SigmaType::SColl(Box::new(SigmaType::SByte)),
                SigmaValue::Coll(CollValue::Bytes(b"9".to_vec())),
            ),
        ]);
        assert_eq!(decode_decimals_r6(&regs), 9);
    }

    #[test]
    fn decode_decimals_falls_back_to_sint() {
        // R6 is SInt directly (not Coll[Byte]). Primary attempt fails
        // the Coll match → fallback to SInt extraction.
        let regs = regs_with(vec![
            (
                SigmaType::SColl(Box::new(SigmaType::SByte)),
                SigmaValue::Coll(CollValue::Bytes(b"name".to_vec())),
            ),
            (
                SigmaType::SColl(Box::new(SigmaType::SByte)),
                SigmaValue::Coll(CollValue::Bytes(b"desc".to_vec())),
            ),
            (SigmaType::SInt, SigmaValue::Int(8)),
        ]);
        assert_eq!(decode_decimals_r6(&regs), 8);
    }

    #[test]
    fn decode_decimals_falls_back_when_bytes_unparseable() {
        // R6 is Coll[Byte] holding non-decimal bytes. Primary parse
        // fails → fallback tries SInt (no match) → default 0.
        let regs = regs_with(vec![
            (
                SigmaType::SColl(Box::new(SigmaType::SByte)),
                SigmaValue::Coll(CollValue::Bytes(b"name".to_vec())),
            ),
            (
                SigmaType::SColl(Box::new(SigmaType::SByte)),
                SigmaValue::Coll(CollValue::Bytes(b"desc".to_vec())),
            ),
            (
                SigmaType::SColl(Box::new(SigmaType::SByte)),
                SigmaValue::Coll(CollValue::Bytes(b"abc".to_vec())),
            ),
        ]);
        assert_eq!(decode_decimals_r6(&regs), 0);
    }

    #[test]
    fn decode_decimals_returns_zero_for_slong_no_int_fallback() {
        // SLong does not match the SInt fallback (Scala asInstanceOf[Int]
        // would throw); default 0.
        let regs = regs_with(vec![
            (
                SigmaType::SColl(Box::new(SigmaType::SByte)),
                SigmaValue::Coll(CollValue::Bytes(b"name".to_vec())),
            ),
            (
                SigmaType::SColl(Box::new(SigmaType::SByte)),
                SigmaValue::Coll(CollValue::Bytes(b"desc".to_vec())),
            ),
            (SigmaType::SLong, SigmaValue::Long(12)),
        ]);
        assert_eq!(decode_decimals_r6(&regs), 0);
    }

    // ---- from_box constructor ----

    #[test]
    fn from_box_pins_creating_box_id_and_emission_amount_to_some() {
        let box_id = d("0101010101010101010101010101010101010101010101010101010101010101");
        let token = Token {
            token_id: d("0202020202020202020202020202020202020202020202020202020202020202"),
            amount: 21_000_000,
        };
        let regs = AdditionalRegisters::empty();
        let t = IndexedToken::from_box(&box_id, &token, &regs);
        assert_eq!(t.token_id, token.token_id);
        assert_eq!(t.creating_box_id, Some(box_id));
        assert_eq!(t.emission_amount, Some(21_000_000));
        // Defaults from missing R4/R5/R6 must be Some(_), not None,
        // for wire-byte parity with Scala.
        assert_eq!(t.name, Some(String::new()));
        assert_eq!(t.description, Some(String::new()));
        assert_eq!(t.decimals, Some(0));
        assert_eq!(t.segment, Segment::empty());
    }

    #[test]
    fn from_box_decodes_eip4_metadata_from_registers() {
        let box_id = d("0303030303030303030303030303030303030303030303030303030303030303");
        let token = Token {
            token_id: d("0404040404040404040404040404040404040404040404040404040404040404"),
            amount: 1_000,
        };
        let regs = regs_with(vec![
            (
                SigmaType::SColl(Box::new(SigmaType::SByte)),
                SigmaValue::Coll(CollValue::Bytes(b"My Token".to_vec())),
            ),
            (
                SigmaType::SColl(Box::new(SigmaType::SByte)),
                SigmaValue::Coll(CollValue::Bytes(b"A test token".to_vec())),
            ),
            (
                SigmaType::SColl(Box::new(SigmaType::SByte)),
                SigmaValue::Coll(CollValue::Bytes(b"4".to_vec())),
            ),
        ]);
        let t = IndexedToken::from_box(&box_id, &token, &regs);
        assert_eq!(t.name.as_deref(), Some("My Token"));
        assert_eq!(t.description.as_deref(), Some("A test token"));
        assert_eq!(t.decimals, Some(4));
    }

    #[test]
    fn from_box_roundtrips_through_wire_format() {
        // Composite check: from_box → wire → read should yield the
        // same record, locking decoder + serializer together.
        let box_id = d("0505050505050505050505050505050505050505050505050505050505050505");
        let token = Token {
            token_id: d("0606060606060606060606060606060606060606060606060606060606060606"),
            amount: 7,
        };
        let regs = regs_with(vec![
            (
                SigmaType::SColl(Box::new(SigmaType::SByte)),
                SigmaValue::Coll(CollValue::Bytes(b"Mainnet".to_vec())),
            ),
            (
                SigmaType::SColl(Box::new(SigmaType::SByte)),
                SigmaValue::Coll(CollValue::Bytes(b"Genesis token".to_vec())),
            ),
            (SigmaType::SInt, SigmaValue::Int(2)),
        ]);
        let t = IndexedToken::from_box(&box_id, &token, &regs);
        roundtrip(&t);
    }

    // ---- add_emission_amount ----

    #[test]
    fn add_emission_amount_increments_existing() {
        let mut t = IndexedToken {
            token_id: TokenId::ZERO,
            creating_box_id: Some(d(
                "0707070707070707070707070707070707070707070707070707070707070707",
            )),
            emission_amount: Some(100),
            name: Some(String::new()),
            description: Some(String::new()),
            decimals: Some(0),
            segment: Segment::empty(),
        };
        t.add_emission_amount(50);
        assert_eq!(t.emission_amount, Some(150));
    }

    #[test]
    fn add_emission_amount_treats_none_as_zero() {
        // Defensive: should never be called on an `empty()` placeholder
        // in practice, but the implementation falls back to 0 for
        // robustness instead of panicking.
        let mut t = IndexedToken::empty(TokenId::ZERO);
        t.add_emission_amount(7);
        assert_eq!(t.emission_amount, Some(7));
    }

    #[test]
    fn add_emission_amount_saturates_on_overflow() {
        let mut t = IndexedToken {
            token_id: TokenId::ZERO,
            creating_box_id: None,
            emission_amount: Some(u64::MAX - 1),
            name: None,
            description: None,
            decimals: None,
            segment: Segment::empty(),
        };
        t.add_emission_amount(100);
        assert_eq!(t.emission_amount, Some(u64::MAX));
    }

    // ---- is_mint predicate ----

    #[test]
    fn is_mint_true_when_token_id_matches_first_input_and_not_in_inputs() {
        let id = d("0808080808080808080808080808080808080808080808080808080808080808");
        let inputs: HashSet<TokenId> = HashSet::new();
        assert!(is_mint(&id, &id, &inputs));
    }

    #[test]
    fn is_mint_false_when_token_id_doesnt_match_first_input() {
        let token_id = d("0909090909090909090909090909090909090909090909090909090909090909");
        let other = d("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let inputs: HashSet<TokenId> = HashSet::new();
        assert!(!is_mint(&token_id, &other, &inputs));
    }

    #[test]
    fn is_mint_false_when_token_id_already_in_input_tokens() {
        let id = d("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
        let mut inputs = HashSet::new();
        inputs.insert(id);
        // Even though id == first_input_box_id, the presence in
        // input_tokens means this is a transfer of an existing token,
        // not a mint.
        assert!(!is_mint(&id, &id, &inputs));
    }

    // ----- error paths -----

    /// The hot path reading `INDEXED_TOKEN` rows enforces the same
    /// trailing-bytes guard the public `store::token::read_token_in`
    /// reader uses.
    #[test]
    fn load_token_into_map_rejects_trailing_bytes() {
        use crate::store::tables::INDEXED_TOKEN;
        use crate::IndexerError;
        use redb::Database;
        use tempfile::TempDir;

        let tmp = TempDir::new().unwrap();
        let db = Database::create(tmp.path().join("hotpath_token.redb")).unwrap();

        let token_id = TokenId::from_bytes([0xCD; 32]);
        let mut w = VlqWriter::new();
        write_indexed_token(&mut w, &IndexedToken::empty(token_id));
        let mut corrupted = w.result();
        corrupted.extend_from_slice(&[0xFF, 0xFF, 0xFF]);

        let key = token_unique_id(&token_id);
        let wtxn = db.begin_write().unwrap();
        {
            let mut table = wtxn.open_table(INDEXED_TOKEN).unwrap();
            table
                .insert(key.as_bytes().as_slice(), corrupted.as_slice())
                .unwrap();
            let mut map = HashMap::new();
            let result = load_token_into_map(&table, &mut map, token_id);
            assert!(
                matches!(
                    result,
                    Err(IndexerError::DbRowLength {
                        context: "indexed_token",
                        ..
                    })
                ),
                "hot path must reject trailing bytes via DbRowLength, got {result:?}",
            );
        }
    }
}
