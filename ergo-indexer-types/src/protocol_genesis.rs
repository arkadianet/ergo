//! Mainnet protocol-genesis box ID whitelist.
//!
//! The Ergo protocol creates 3 boxes before block 1: emission box,
//! no-premine box, foundation box. Their IDs are deterministic outputs
//! of the canonical mainnet `ErgoState.genesisBoxes` constructor (Scala
//! `nodeView/state/ErgoState.scala:241-263`). The values below are the
//! `boxId` fields from `test-vectors/mainnet/genesis_boxes.json`.
//!
//! Why this whitelist exists: the ExtraIndexer never seeds these boxes
//! into its `box_table` (Scala `ExtraIndexer.scala:79` initializes the
//! `boxes` HashMap empty; we mirror that to preserve `globalBoxIndex`
//! numbering). On the first spend of any of these boxes (foundation at
//! mainnet h=3850; no-premine never spent to date; emission's first
//! spend is rolled forward by h=1's coinbase tx and so resolves
//! normally from h=2 onward), the apply-path lookup would otherwise
//! halt with `InputMissing`. Scala silently absorbs these spends with
//! a `log.warn` (`ExtraIndexer.scala:331`); we match that behavior
//! only for these 3 known IDs and keep `InputMissing` terminal for
//! every other unknown input — the latter still indicates a real
//! indexer/chain divergence and should halt.

/// Mainnet protocol-genesis box IDs (foundation, no-premine, emission).
/// Order is the same as `genesis_boxes.json`.
pub const PROTOCOL_GENESIS_BOX_IDS_MAINNET: [[u8; 32]; 3] = [
    // Emission contract — re-spent every block from h=1.
    parse_hex32(b"b69575e11c5c43400bfead5976ee0d6245a1168396b2e2a4f384691f275d501c"),
    // No-premine box — never spent on mainnet to date.
    parse_hex32(b"b8ce8cfe331e5eadfb0783bdc375c94413433f65e1e45857d71550d42e4d83bd"),
    // Foundation box — first spent at mainnet h=3850.
    parse_hex32(b"5527430474b673e4aafb08e0079c639de23e6a17e87edd00f78662b43c88aeda"),
];

/// True if `id` is one of the 3 mainnet protocol-genesis box IDs.
/// Used by `apply_block` to absorb their first spend silently rather
/// than halt with `InputMissing`.
pub fn is_protocol_genesis_box(id: &[u8; 32]) -> bool {
    PROTOCOL_GENESIS_BOX_IDS_MAINNET.contains(id)
}

const fn parse_hex32(s: &[u8; 64]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = (hex_digit(s[i * 2]) << 4) | hex_digit(s[i * 2 + 1]);
        i += 1;
    }
    out
}

const fn hex_digit(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => panic!("bad hex digit in PROTOCOL_GENESIS_BOX_IDS"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_hex32_round_trips_first_byte() {
        // Spot-check that the const hex parser matches the leading bytes
        // from genesis_boxes.json. If parse_hex32 ever drifts this fires.
        assert_eq!(PROTOCOL_GENESIS_BOX_IDS_MAINNET[0][0], 0xb6);
        assert_eq!(PROTOCOL_GENESIS_BOX_IDS_MAINNET[1][0], 0xb8);
        assert_eq!(PROTOCOL_GENESIS_BOX_IDS_MAINNET[2][0], 0x55);
        assert_eq!(PROTOCOL_GENESIS_BOX_IDS_MAINNET[2][31], 0xda);
    }

    #[test]
    fn whitelist_membership() {
        // Foundation box ID byte-by-byte (matches genesis_boxes.json).
        let foundation: [u8; 32] = [
            0x55, 0x27, 0x43, 0x04, 0x74, 0xb6, 0x73, 0xe4, 0xaa, 0xfb, 0x08, 0xe0, 0x07, 0x9c,
            0x63, 0x9d, 0xe2, 0x3e, 0x6a, 0x17, 0xe8, 0x7e, 0xdd, 0x00, 0xf7, 0x86, 0x62, 0xb4,
            0x3c, 0x88, 0xae, 0xda,
        ];
        assert!(is_protocol_genesis_box(&foundation));
        assert!(!is_protocol_genesis_box(&[0u8; 32]));
    }
}
