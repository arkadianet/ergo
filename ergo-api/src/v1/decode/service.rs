//! The decode service (O6) — the ONE entrypoint every box-returning surface
//! calls to populate `decoded`: `boxes/{id}?decode`, the box list routes,
//! `POST /boxes/decode`, and (reused) tx-intelligence output previews all
//! funnel through [`decode_box`]. No consensus evaluation — pure
//! deserialization + register reads + a bounded registry lookup. A malformed
//! tree or ill-typed register never errors the box; it yields
//! `contract: null` / `confidence: heuristic` (fail-soft, `bytemplate.rs:163`
//! precedent).

use std::collections::BTreeMap;

use ergo_primitives::reader::VlqReader;
use ergo_ser::ergo_tree::{template_hash_from_bytes, tree_hash_from_bytes};
use ergo_ser::sigma_type::SigmaType;
use ergo_ser::sigma_value::{read_constant, SigmaValue};
use serde_json::{json, Value};

use super::decoders::render_state;
use super::registry::match_box;
use super::value::decode_value;

/// The minimal box facts a decoder needs — assembled by the caller from an
/// indexer box, a block-embedded output, or an off-chain box's bytes. Registers
/// arrive already parsed (type + value) so no decoder re-deserializes.
pub struct DecodeInput<'a> {
    /// nanoERG value the box holds.
    pub value: u64,
    /// `(token_id hex, amount)` for each asset on the box, in box order.
    pub tokens: &'a [(String, u64)],
    /// Registers `R4..=R9` decoded to `(type, value)`; absent registers are
    /// simply missing keys.
    pub registers: &'a BTreeMap<String, (SigmaType, SigmaValue)>,
}

/// Parse each raw register hex (`{"R4":"05a0..."}`) into a typed
/// `(SigmaType, SigmaValue)`. A register that fails to hex-decode or parse is
/// **skipped** (fail-soft) rather than erroring the whole box.
fn parse_registers(raw: &BTreeMap<String, String>) -> BTreeMap<String, (SigmaType, SigmaValue)> {
    let mut out = BTreeMap::new();
    for (name, hex_str) in raw {
        let Ok(bytes) = hex::decode(hex_str.trim()) else {
            continue;
        };
        let mut reader = VlqReader::new(&bytes);
        if let Ok((ty, val)) = read_constant(&mut reader) {
            out.insert(name.clone(), (ty, val));
        }
    }
    out
}

/// Render the parsed registers into the `{ "R4": {type,value}, … }` typed map.
fn typed_registers(parsed: &BTreeMap<String, (SigmaType, SigmaValue)>) -> Value {
    let mut map = serde_json::Map::new();
    for (name, (ty, val)) in parsed {
        map.insert(name.clone(), decode_value(ty, val));
    }
    Value::Object(map)
}

/// Build the `decoded` object for a box: its typed registers plus the matched
/// protocol contract (`null` when nothing in the registry matched — a raw box
/// is never *less* useful with `decode=true`; `null` is deliberate, not error).
///
/// `ergo_tree_hex` is the box script; `value`/`tokens`/`registers_hex` are the
/// box body. This is the shared O6 seam — same shape for on-chain and off-chain
/// boxes.
pub fn decode_box(
    ergo_tree_hex: &str,
    value: u64,
    tokens: &[(String, u64)],
    registers_hex: &BTreeMap<String, String>,
) -> Value {
    decode_box_bytes(
        hex::decode(ergo_tree_hex.trim()).ok().as_deref(),
        value,
        tokens,
        registers_hex,
    )
}

/// [`decode_box`] over pre-decoded tree bytes — for callers that already hold
/// them (e.g. the off-chain route, which decodes once for the address), so the
/// hex is never decoded twice. `None` = the tree was not decodable hex; the
/// register/token decode still runs.
pub fn decode_box_bytes(
    tree_bytes: Option<&[u8]>,
    value: u64,
    tokens: &[(String, u64)],
    registers_hex: &BTreeMap<String, String>,
) -> Value {
    let parsed = parse_registers(registers_hex);
    let registers_json = typed_registers(&parsed);

    // Contract keys: hash the tree bytes. A tree that fails to hash (malformed /
    // soft-fork-wrapped) simply yields no hash key — token matching still works.
    let (template_hex, tree_hex) = match tree_bytes {
        Some(bytes) => (
            template_hash_from_bytes(bytes).ok().map(hex::encode),
            tree_hash_from_bytes(bytes).ok().map(hex::encode),
        ),
        None => (None, None),
    };
    let token_ids: Vec<&str> = tokens.iter().map(|(id, _)| id.as_str()).collect();

    let contract = match match_box(&token_ids, template_hex.as_deref(), tree_hex.as_deref()) {
        Some(m) if m.entry.decodable => {
            let input = DecodeInput {
                value,
                tokens,
                registers: &parsed,
            };
            let (state, downgraded) = render_state(m.matcher.decoder, &input, m.matcher.key);
            let confidence = if downgraded {
                "heuristic"
            } else {
                m.confidence
            };
            json!({
                "protocol_id": m.entry.id,
                "protocol_name": m.entry.name,
                "version": m.entry.version,
                "family": m.entry.family.wire(),
                "box_role": m.matcher.box_role,
                "matched_by": m.matched_by.wire(),
                "confidence": confidence,
                "reference": m.entry.reference,
                "state": state,
            })
        }
        // Matched a stub entry (recognized but not yet decodable), or no match:
        // either way the contract is honestly `null` — no fabricated state.
        _ => Value::Null,
    };

    json!({
        "registers": registers_json,
        "contract": contract,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v1::decode::registry::{SIGUSD_V2_RC_TOKEN, SIGUSD_V2_SC_TOKEN};

    // ----- helpers -----

    const SIGUSD_V2_BANK_NFT: &str =
        "7d672d1def471720ca5b1dd6a56b48a83db78f5510c2a48800a5e2588f43c9e5";

    /// A minimal non-protocol P2PK-ish tree hex (constant-segregated ProveDlog).
    /// Only used to prove an unrecognized box decodes to `contract: null`.
    const PLAIN_TREE_HEX: &str =
        "0008cd02a7955281885bf0f0ca4a48678848c4a9d301d5cabd2d3428f77c2b1d9761b6e6";

    /// Encode a `Long` register the way the wire does: type byte `0x05` (SLong)
    /// followed by the zig-zag VLQ value — via the library writer, so the test
    /// oracle is the real codec, not a hand-rolled byte string.
    fn long_register_hex(n: i64) -> String {
        use ergo_primitives::writer::VlqWriter;
        use ergo_ser::sigma_value::write_constant;
        let mut w = VlqWriter::new();
        write_constant(&mut w, &SigmaType::SLong, &SigmaValue::Long(n)).unwrap();
        hex::encode(w.result())
    }

    /// A synthetic SigmaUSD v2 bank box matching the documented AgeUSD layout.
    /// SYNTHETIC (no live mainnet box was reachable at authoring time): the token
    /// ids + register semantics are the verified layout; the numbers are chosen.
    fn synthetic_bank_box() -> (u64, Vec<(String, u64)>, BTreeMap<String, String>) {
        let value = 1_402_000_000_000_000u64; // reserve nanoERG
        let tokens = vec![
            (SIGUSD_V2_BANK_NFT.to_string(), 1),
            (SIGUSD_V2_SC_TOKEN.to_string(), 9_000_000_000u64),
            (SIGUSD_V2_RC_TOKEN.to_string(), 8_000_000_000u64),
        ];
        let mut regs = BTreeMap::new();
        regs.insert("R4".to_string(), long_register_hex(1_200_345)); // circ SigUSD
        regs.insert("R5".to_string(), long_register_hex(9_930_021)); // circ SigRSV
        (value, tokens, regs)
    }

    // ----- happy path -----

    #[test]
    fn decode_box_sigmausd_bank_reports_reserve_and_circulating() {
        let (value, tokens, regs) = synthetic_bank_box();
        let decoded = decode_box(PLAIN_TREE_HEX, value, &tokens, &regs);

        let contract = &decoded["contract"];
        assert_eq!(contract["protocol_id"], "sigmausd");
        assert_eq!(contract["family"], "bank");
        assert_eq!(contract["box_role"], "bank");
        assert_eq!(contract["matched_by"], "identifying_token");
        assert_eq!(contract["confidence"], "exact");

        let state = &contract["state"];
        assert_eq!(state["peg_asset"], "USD");
        assert_eq!(state["reserve_nanoerg"], "1402000000000000");
        assert_eq!(state["circulating_sigusd"], "1200345");
        assert_eq!(state["circulating_sigrsv"], "9930021");
        assert_eq!(state["sigusd_in_bank"], "9000000000");
        assert_eq!(state["sigrsv_in_bank"], "8000000000");
        assert_eq!(state["oracle_derived_price_available"], false);
    }

    #[test]
    fn decode_box_always_populates_typed_registers() {
        let (value, tokens, regs) = synthetic_bank_box();
        let decoded = decode_box(PLAIN_TREE_HEX, value, &tokens, &regs);
        // Registers are typed even independently of contract matching.
        assert_eq!(decoded["registers"]["R4"]["type"], "long");
        assert_eq!(decoded["registers"]["R4"]["value"], "1200345");
        assert_eq!(decoded["registers"]["R5"]["type"], "long");
    }

    // ----- error paths / honesty -----

    #[test]
    fn decode_box_unrecognized_yields_null_contract() {
        // A plain box with no known NFT and a non-protocol tree: registers still
        // decode, but the contract is honestly null (never fabricated).
        let regs = BTreeMap::new();
        let tokens: Vec<(String, u64)> = vec![];
        let decoded = decode_box(PLAIN_TREE_HEX, 1_000_000, &tokens, &regs);
        assert!(decoded["contract"].is_null());
        assert!(decoded["registers"].is_object());
    }

    #[test]
    fn decode_box_stub_protocol_token_does_not_match() {
        // A token that is NOT a registered identifying NFT must not match; the
        // stub entries (spectrum/dexy/…) carry no matchers, so nothing fires.
        let regs = BTreeMap::new();
        let tokens = vec![(
            "1111111111111111111111111111111111111111111111111111111111111111".to_string(),
            1u64,
        )];
        let decoded = decode_box(PLAIN_TREE_HEX, 1_000_000, &tokens, &regs);
        assert!(decoded["contract"].is_null());
    }

    #[test]
    fn decode_box_bank_missing_registers_downgrades_to_heuristic() {
        // Matched the bank NFT but the circulating counters are absent: the
        // decoder stays honest — confidence downgrades and the counts are null.
        let (value, tokens, _regs) = synthetic_bank_box();
        let empty = BTreeMap::new();
        let decoded = decode_box(PLAIN_TREE_HEX, value, &tokens, &empty);
        assert_eq!(decoded["contract"]["confidence"], "heuristic");
        assert!(decoded["contract"]["state"]["circulating_sigusd"].is_null());
        // Reserve is still truthful (it is the box value, not a register).
        assert_eq!(
            decoded["contract"]["state"]["reserve_nanoerg"],
            value.to_string()
        );
    }

    #[test]
    fn decode_box_malformed_tree_still_matches_by_token() {
        // Token matching is independent of the tree hashing: a garbage tree that
        // fails template/tree hashing must not stop an NFT match.
        let (value, tokens, regs) = synthetic_bank_box();
        let decoded = decode_box("zzz-not-hex", value, &tokens, &regs);
        assert_eq!(decoded["contract"]["protocol_id"], "sigmausd");
    }
}
