use ergo_primitives::digest::ModifierId;
use ergo_primitives::reader::{ReadError, VlqReader};
use ergo_primitives::writer::VlqWriter;

use crate::error::WriteError;
use crate::transaction::{read_transaction, write_transaction, Transaction};

/// A block's transactions section: the header it belongs to plus the
/// ordered list of transactions. Authenticated by the header's
/// `transactions_root` (Merkle over `transaction_id`s in order).
#[derive(Debug, Clone, PartialEq)]
pub struct BlockTransactions {
    /// Identifier of the block header these transactions extend.
    pub header_id: ModifierId,
    /// Transactions in their consensus-significant order.
    pub transactions: Vec<Transaction>,
}

/// Maximum transactions in a block. Doubles as the threshold above
/// which a leading `u32` is interpreted as a v2+ version marker (Scala:
/// `BlockTransactions.MaxTransactionsInBlock = 10_000_000`).
const MAX_TRANSACTIONS_IN_BLOCK: u32 = 10_000_000;

/// Initial `Vec::with_capacity` hint for the transactions list. Bounded
/// at 1024 so a hostile peer that claims `count = MAX_TRANSACTIONS_IN_BLOCK`
/// cannot force the parser to reserve `count * size_of::<Transaction>()`
/// (≈ 720 MiB) before reading the first tx byte. The Vec still grows on
/// `push` up to the hard cap above; this only bounds the *initial*
/// reservation. Honest blocks at mainnet sizes (a few thousand txs at
/// most) hit at most one or two reallocations.
const TRANSACTIONS_VEC_SOFT_CAP: usize = 1_024;

/// V1 (Autolykos v1 era) BlockTransactions wire encoding:
/// `header_id || u32 count || tx*`. Mirrors Scala's
/// `BlockTransactionsSerializer` for `block_version == 1`.
///
/// **Use [`write_block_transactions_with_version`] for v2+ blocks**
/// (post-Autolykos-v2, height >= 417,792). This v1-only function
/// stays as a back-compat alias so test code that doesn't care
/// about the version marker keeps working.
pub fn write_block_transactions(
    w: &mut VlqWriter,
    bt: &BlockTransactions,
) -> Result<(), WriteError> {
    write_block_transactions_with_version(w, bt, 1)
}

/// Block-version-aware BlockTransactions writer. For
/// `block_version == 1` emits the legacy
/// `header_id || u32 count || tx*` shape. For a *signed* `block_version > 1`
/// (i.e. `2..=127` — Scala treats the version as a signed `Byte`) emits Scala's
/// v2+ shape:
/// `header_id || u32 (MAX_TRANSACTIONS_IN_BLOCK + block_version) ||
///  u32 count || tx*` — the version marker that
/// [`read_block_transactions`] auto-detects on the read side. A malformed
/// `block_version > 127` is signed-negative, so it is markerless (v1 shape),
/// matching the reference; this is unreachable on a PoW-valid header.
///
/// Required for byte-fidelity checks: reconstructed canonical bytes
/// must match the blake2b256 of
/// `compute_section_id(TYPE_BLOCK_TRANSACTIONS, header_id,
/// header.transactions_root)` for the indexer/validator to accept the
/// persisted section. Without the marker, a v2+ block re-serialized
/// from parsed form would not round-trip the persisted bytes — the
/// production path stores wire bytes verbatim and never reaches this
/// writer, but reconstruction paths do.
pub fn write_block_transactions_with_version(
    w: &mut VlqWriter,
    bt: &BlockTransactions,
    block_version: u8,
) -> Result<(), WriteError> {
    w.put_bytes(bt.header_id.as_bytes());
    // Scala `BlockTransactionsSerializer` gates the v2+ marker on a SIGNED
    // `Byte` comparison (`blockVersion > 1`). Agrees for all real versions
    // (1-4); a malformed version > 127 is signed-negative, so no marker is
    // written — matching the reference. (Unreachable in practice: such a block
    // version cannot exist on a PoW-valid header.)
    if (block_version as i8) > 1 {
        w.put_u32(MAX_TRANSACTIONS_IN_BLOCK + block_version as u32);
    }
    w.put_u32(bt.transactions.len() as u32);
    for tx in &bt.transactions {
        write_transaction(w, tx)?;
    }
    Ok(())
}

/// Decode the wire form produced by either [`write_block_transactions`]
/// (v1) or [`write_block_transactions_with_version`] (any version). The
/// reader auto-detects the optional v2+ marker by checking whether the
/// first VLQ-`u32` after `header_id` exceeds `MAX_TRANSACTIONS_IN_BLOCK`.
/// Reads the block-transactions section. Delegates to
/// [`read_block_transactions_with_group_elements`] and drops the points; as a
/// result the reader's group-element sideband is drained on return (rather than
/// left accumulated as in the standalone form). No caller inspects the sideband
/// after this call, and a drained sideband is the safer post-condition — group
/// elements from this section never leak into a subsequent unrelated read.
pub fn read_block_transactions(r: &mut VlqReader) -> Result<BlockTransactions, ReadError> {
    let (block_transactions, _group_elements) = read_block_transactions_with_group_elements(r)?;
    Ok(block_transactions)
}

/// Group-element points per transaction in a block, index-aligned 1:1 with
/// `BlockTransactions::transactions`; inner `Vec` holds one tx's 33-byte points.
pub type PerTxGroupElements = Vec<Vec<[u8; 33]>>;

/// Like [`read_block_transactions`], but also returns the group-element points
/// collected during each transaction's parse, index-aligned 1:1 with
/// `transactions`.
///
/// The `VlqReader` records every 33-byte group element it reads onto a
/// crypto-free sideband; draining it after each transaction yields exactly that
/// transaction's points. The block validator curve-checks these (Scala curve-
/// checks group elements at deserialize) — collecting them here, at the single
/// authoritative parse, lets `validate_transaction_parsed` skip re-deserializing
/// each transaction just to re-collect them.
pub fn read_block_transactions_with_group_elements(
    r: &mut VlqReader,
) -> Result<(BlockTransactions, PerTxGroupElements), ReadError> {
    let header_id = ModifierId::from_bytes(r.get_array::<32>()?);

    // Scala serializer writes a version marker for blocks with version > 1:
    // putUInt(MaxTransactionsInBlock + blockVersion) before the tx count.
    // If the first VLQ > MaxTransactionsInBlock, it's a version marker.
    let ver_or_count = r.get_u32_exact()?;
    let count = if ver_or_count > MAX_TRANSACTIONS_IN_BLOCK {
        // v2+ marker: ver_or_count = MAX_TRANSACTIONS_IN_BLOCK + block_version,
        // the real tx count follows. The v1 branch (else arm) is bounded
        // by the marker check itself; the post-marker count needs an
        // explicit cap so a peer cannot send `count = i32::MAX` and
        // trigger a multi-GiB Vec::with_capacity below.
        let post_marker_count = r.get_u32_exact()?;
        if post_marker_count > MAX_TRANSACTIONS_IN_BLOCK {
            return Err(ReadError::InvalidData(format!(
                "BlockTransactions v2 count {post_marker_count} > cap {MAX_TRANSACTIONS_IN_BLOCK}"
            )));
        }
        post_marker_count as usize
    } else {
        ver_or_count as usize
    };

    // Discard any points read before the first transaction (header_id/count
    // carry none, but a reused reader could) so each per-tx Vec holds only that
    // transaction's points.
    let _ = r.take_group_elements();

    let mut transactions = Vec::with_capacity(count.min(TRANSACTIONS_VEC_SOFT_CAP));
    let mut per_tx_group_elements = Vec::with_capacity(count.min(TRANSACTIONS_VEC_SOFT_CAP));
    for tx_idx in 0..count {
        let tx = read_transaction(r)
            .map_err(|e| ReadError::InvalidData(format!("tx[{tx_idx}]: {e}")))?;
        transactions.push(tx);
        per_tx_group_elements.push(r.take_group_elements());
    }
    Ok((
        BlockTransactions {
            header_id,
            transactions,
        },
        per_tx_group_elements,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ergo_box::ErgoBoxCandidate;
    use crate::ergo_tree::ErgoTree;
    use crate::input::{ContextExtension, Input, SpendingProof};
    use crate::opcode::{Body, Expr};
    use crate::register::AdditionalRegisters;
    use crate::sigma_type::SigmaType;
    use crate::sigma_value::SigmaValue;
    use ergo_primitives::digest::Digest32;

    // ----- helpers -----

    fn simple_body() -> Body {
        Expr::Const {
            tpe: SigmaType::SBoolean,
            val: SigmaValue::Boolean(true),
        }
    }

    fn size_delimited_tree() -> ErgoTree {
        ErgoTree {
            version: 0,
            has_size: true,
            constant_segregation: false,
            constants: vec![],
            body: simple_body(),
        }
    }

    fn make_box_id(fill: u8) -> Digest32 {
        Digest32::from_bytes([fill; 32])
    }

    fn make_candidate(value: u64) -> ErgoBoxCandidate {
        ErgoBoxCandidate::new(
            value,
            size_delimited_tree(),
            100,
            vec![],
            AdditionalRegisters::empty(),
        )
        .unwrap()
    }

    fn make_tx(box_fill: u8) -> Transaction {
        Transaction {
            inputs: vec![Input {
                box_id: make_box_id(box_fill),
                spending_proof: SpendingProof::new(vec![0xAB, 0xCD], ContextExtension::empty())
                    .unwrap(),
            }],
            data_inputs: vec![],
            output_candidates: vec![make_candidate(1_000_000)],
        }
    }

    // ----- round-trips -----

    #[test]
    fn block_transactions_roundtrip_empty() {
        let bt = BlockTransactions {
            header_id: ModifierId::from_bytes([0x11; 32]),
            transactions: vec![],
        };
        let mut w = VlqWriter::new();
        write_block_transactions(&mut w, &bt).unwrap();
        let data = w.result();
        let mut r = VlqReader::new(&data);
        let decoded = read_block_transactions(&mut r).unwrap();
        assert!(r.is_empty(), "leftover bytes");
        assert_eq!(decoded, bt);
    }

    #[test]
    fn block_transactions_roundtrip_one_tx() {
        let bt = BlockTransactions {
            header_id: ModifierId::from_bytes([0x22; 32]),
            transactions: vec![make_tx(0xAA)],
        };
        let mut w = VlqWriter::new();
        write_block_transactions(&mut w, &bt).unwrap();
        let data = w.result();
        let mut r = VlqReader::new(&data);
        let decoded = read_block_transactions(&mut r).unwrap();
        assert!(r.is_empty(), "leftover bytes");
        assert_eq!(decoded, bt);
    }

    /// Pin Scala-canonical v2 wire format for the new
    /// `write_block_transactions_with_version`. The v2+ shape
    /// inserts a `MAX_TRANSACTIONS_IN_BLOCK + block_version` u32
    /// marker between `header_id` and `count` (matching
    /// `BlockTransactionsSerializer` for blockVersion > 1). The
    /// `read` side auto-detects the marker; this test pins that the
    /// write side emits the matching marker AND that `write → read`
    /// roundtrip recovers the same struct, so read and write stay
    /// symmetric on the v2 marker.
    #[test]
    fn block_transactions_v2_writer_emits_version_marker() {
        let bt = BlockTransactions {
            header_id: ModifierId::from_bytes([0x33; 32]),
            transactions: vec![make_tx(0xBB), make_tx(0xCC)],
        };
        // Write v1 vs v2 — v2 has the additional version-marker
        // VLQ between header_id and count, so v2 bytes should be
        // strictly longer.
        let mut w_v1 = VlqWriter::new();
        write_block_transactions_with_version(&mut w_v1, &bt, 1).unwrap();
        let v1_bytes = w_v1.result();

        let mut w_v2 = VlqWriter::new();
        write_block_transactions_with_version(&mut w_v2, &bt, 2).unwrap();
        let v2_bytes = w_v2.result();

        assert!(
            v2_bytes.len() > v1_bytes.len(),
            "v2 wire format must include version marker (longer than v1)"
        );

        // Decode v2 with the auto-detecting reader and verify the
        // marker arithmetic by checking the parsed_block_version
        // path. We can't easily extract just the marker without
        // duplicating the VLQ decode logic; instead pin the
        // round-trip and the v2-vs-v1 length differential.
        let mut r = VlqReader::new(&v2_bytes);
        let decoded = read_block_transactions(&mut r).unwrap();
        assert!(r.is_empty(), "leftover bytes after v2 roundtrip");
        assert_eq!(decoded, bt);

        // v1 also roundtrips cleanly.
        let mut r = VlqReader::new(&v1_bytes);
        let decoded_v1 = read_block_transactions(&mut r).unwrap();
        assert!(r.is_empty(), "leftover bytes after v1 roundtrip");
        assert_eq!(decoded_v1, bt);
    }

    /// Symmetric round-trip across v1, v2, v3, v4 to pin the version
    /// marker formula. v1 omits the marker; signed `block_version > 1`
    /// (2..=127) emits `MAX_TRANSACTIONS_IN_BLOCK + block_version`.
    #[test]
    fn block_transactions_v_writer_roundtrip_for_all_versions() {
        let bt = BlockTransactions {
            header_id: ModifierId::from_bytes([0x44; 32]),
            transactions: vec![make_tx(0xDD)],
        };
        for v in [1u8, 2, 3, 4] {
            let mut w = VlqWriter::new();
            write_block_transactions_with_version(&mut w, &bt, v).unwrap();
            let data = w.result();
            let mut r = VlqReader::new(&data);
            let decoded = read_block_transactions(&mut r).unwrap();
            assert!(r.is_empty(), "version {v}: leftover bytes");
            assert_eq!(decoded, bt, "version {v}: roundtrip mismatch");
        }
    }

    // ----- error paths -----

    /// Build a v2+ marker preamble (header_id + marker only, no count or
    /// txs) so callers can append a hostile or boundary count and assert
    /// where the read fails.
    fn v2_marker_preamble(block_version: u8) -> Vec<u8> {
        let mut w = VlqWriter::new();
        w.put_bytes(&[0xAA; 32]); // header_id
        w.put_u32(MAX_TRANSACTIONS_IN_BLOCK + block_version as u32);
        w.result()
    }

    #[test]
    fn read_block_transactions_v2_count_above_cap_rejects_before_alloc() {
        // Hostile post-marker count = i32::MAX. The cap check must
        // fire on the count itself, before Vec::with_capacity attempts
        // a multi-GiB allocation and before any read_transaction can
        // hit UnexpectedEnd. No transaction bytes follow — a
        // truncation-based error would prove the cap gate was skipped.
        let mut bytes = v2_marker_preamble(2);
        let mut tail = VlqWriter::new();
        tail.put_u32(i32::MAX as u32);
        bytes.extend_from_slice(&tail.result());
        let mut r = VlqReader::new(&bytes);
        let err = read_block_transactions(&mut r).expect_err("hostile v2 count");
        match err {
            ReadError::InvalidData(msg) => {
                assert!(msg.contains("v2 count"), "wrong message: {msg}");
                assert!(msg.contains("10000000"), "cap must be cited: {msg}");
            }
            other => panic!("expected InvalidData (cap), got {other:?}"),
        }
    }

    #[test]
    fn read_block_transactions_v2_count_cap_boundary_rejects_one_past() {
        // Off-by-one pin: cap is MAX_TRANSACTIONS_IN_BLOCK. cap + 1 must
        // reject; the gate must be `>` cap, not `>=`. Pairs with the
        // honest-acceptance assertion in
        // `read_block_transactions_v2_count_below_cap_proceeds_past_gate`.
        let mut bytes = v2_marker_preamble(2);
        let mut tail = VlqWriter::new();
        tail.put_u32(MAX_TRANSACTIONS_IN_BLOCK + 1);
        bytes.extend_from_slice(&tail.result());
        let mut r = VlqReader::new(&bytes);
        assert!(matches!(
            read_block_transactions(&mut r),
            Err(ReadError::InvalidData(_))
        ));
    }

    #[test]
    fn read_block_transactions_v2_count_below_cap_proceeds_past_gate() {
        // Counterpart to the cap-violation tests above. With a count
        // well under the cap and no transaction bytes following, the
        // error must come from EOF / VLQ inside `read_transaction` —
        // not from the new cap gate. This proves the gate does not
        // spuriously reject honest counts.
        let mut bytes = v2_marker_preamble(2);
        let mut tail = VlqWriter::new();
        tail.put_u32(5); // 5 << MAX_TRANSACTIONS_IN_BLOCK
        bytes.extend_from_slice(&tail.result());
        let mut r = VlqReader::new(&bytes);
        let err = read_block_transactions(&mut r).expect_err("EOF on tx parse");
        match err {
            ReadError::InvalidData(msg) => {
                assert!(
                    !msg.contains("v2 count"),
                    "cap gate must not fire below cap: {msg}"
                );
            }
            ReadError::UnexpectedEnd { .. } | ReadError::Vlq(_) => {} // expected
            other => panic!("expected EOF/VLQ error past gate, got {other:?}"),
        }
    }

    #[test]
    fn read_block_transactions_v2_count_at_hard_cap_bounds_initial_alloc() {
        // Regression pin for the soft-alloc cap. A hostile peer claims
        // `count = MAX_TRANSACTIONS_IN_BLOCK` (the largest value the
        // hard-cap gate permits) but supplies no transaction bytes.
        //
        // Without TRANSACTIONS_VEC_SOFT_CAP, the parser would call
        // `Vec::with_capacity(10_000_000)` and reserve ≈ 720 MiB
        // (`10_000_000 * size_of::<Transaction>`) before reading
        // a single tx byte — a small-message → large-allocation
        // amplification DoS.
        //
        // The fact that this test completes promptly without OOM-ing
        // the test process IS the soft-cap proof. We also assert the
        // expected EOF-on-tx-parse error so the call path is pinned.
        let mut bytes = v2_marker_preamble(2);
        let mut tail = VlqWriter::new();
        tail.put_u32(MAX_TRANSACTIONS_IN_BLOCK);
        bytes.extend_from_slice(&tail.result());
        let mut r = VlqReader::new(&bytes);
        let err = read_block_transactions(&mut r)
            .expect_err("must error on missing tx bytes, but must not OOM");
        match err {
            ReadError::UnexpectedEnd { .. } | ReadError::Vlq(_) => {} // expected past the gate
            ReadError::InvalidData(msg) => {
                assert!(
                    !msg.contains("v2 count"),
                    "hard-cap gate must not fire at exactly cap: {msg}"
                );
            }
            other => panic!("unexpected error past gate: {other:?}"),
        }
    }

    #[test]
    fn v2_marker_gate_is_signed_no_marker_above_version_127() {
        // Scala's v2+ marker gate is a signed `Byte` comparison. A version > 127
        // is signed-negative, so NO marker is written — the bytes match the v1
        // (markerless) layout. Pins the signed gate for the unreachable > 127
        // case; real versions 1-4 are unaffected.
        let bt = BlockTransactions {
            header_id: ModifierId::from_bytes([0x33; 32]),
            transactions: vec![make_tx(0x01)],
        };
        let ser = |version: u8| {
            let mut w = VlqWriter::new();
            write_block_transactions_with_version(&mut w, &bt, version).unwrap();
            w.result()
        };
        let v1 = ser(1);
        // The signed transition is exactly at 127/128: 127 as i8 is +127
        // (> 1 → marker); 128 as i8 is -128 (not > 1 → markerless), as is 195.
        assert!(
            ser(127).len() > v1.len(),
            "version 127 is signed-positive (> 1) and must carry the marker",
        );
        assert_eq!(
            ser(128),
            v1,
            "version 128 is signed -128 (not > 1) → no marker, matching v1 layout",
        );
        assert_eq!(
            ser(195),
            v1,
            "version > 127 must write no v2 marker (signed gate), matching v1 layout",
        );
        assert!(
            ser(2).len() > v1.len(),
            "a real v2 block carries the marker (longer than v1)",
        );
    }
}
