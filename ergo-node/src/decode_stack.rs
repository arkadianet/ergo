//! Stack floor for every thread that can deserialize peer-supplied bytes.
//!
//! Deserialization is recursive. Its depth is bounded by `MaxTreeDepth` (110
//! levels shared across expressions, nested box scripts and `SigmaBoolean`
//! trees) and its size by the 4 KiB proposition window, so the worst case is
//! finite and small — but the fattest frames, the nested box <-> tree cycle,
//! still need 1-1.5 MiB of stack for the deepest descent a peer can force on
//! the transaction surface, measured in a release build (more in debug).
//! Tokio's default worker stack is 2 MiB, and Rayon inherits std's default,
//! which left that descent within half a MiB of an abort.
//!
//! 8 MiB is a floor with over 5x margin on the measured worst case, not a tight
//! bound. Stacks commit lazily, so the cost is address space, not resident
//! memory.
//!
//! It is a shock absorber, not the safety property. What keeps malformed input
//! from being ACCEPTED is the shared depth budget in `ergo-ser`, checked against
//! the reference; a larger stack makes an unbounded-recursion regression quieter,
//! not louder. The guard test below is what keeps the number honest: it runs the
//! worst-case descent on HALF the floor, so frame growth turns CI red long before
//! it could reach production.

/// Stack size, in bytes, for the Tokio runtime's threads (workers and blocking
/// pool) and Rayon's global pool. See the module docs for how it was chosen.
pub const DECODE_THREAD_STACK_BYTES: usize = 8 * 1024 * 1024;

#[cfg(test)]
mod tests {
    use super::DECODE_THREAD_STACK_BYTES;
    use ergo_primitives::reader::{ReadError, VlqReader};
    use ergo_ser::transaction::read_transaction;

    // ----- helpers -----

    /// A one-output transaction whose output proposition nests `levels` `SBox`
    /// constants: each level is a size-delimited v0 tree whose body is an
    /// `SBox` constant carrying the next level's box. This is the fattest-frame
    /// recursion the decoder has (every level re-enters the tree reader through
    /// a box), reached through the surface a peer actually sends.
    fn nested_box_transaction(levels: usize) -> Vec<u8> {
        fn box_bytes(tree: &[u8]) -> Vec<u8> {
            let mut b = vec![0x01u8]; // value = 1 nanoErg
            b.extend_from_slice(tree); // proposition
            b.extend_from_slice(&[0x00, 0x00, 0x00]); // height, 0 tokens, 0 registers
            b.extend_from_slice(&[0u8; 32]); // transaction id
            b.extend_from_slice(&[0x00, 0x00]); // output index
            b
        }
        let mut tree = vec![0x00u8, 0x08, 0xD3]; // v0 sizeless sigmaProp(true)
        for _ in 0..levels {
            let mut body = vec![0x63u8]; // SBox inline constant
            body.extend_from_slice(&box_bytes(&tree));
            let mut next = vec![0x08u8]; // v0, size-delimited
            ergo_primitives::vlq::encode_vlq_into(body.len() as u64, &mut next);
            next.extend_from_slice(&body);
            tree = next;
        }
        // 0 inputs, 0 data inputs, 0 tokens, 1 output
        let mut tx = vec![0x00u8, 0x00, 0x00, 0x01];
        tx.push(0x01); // output value
        tx.extend_from_slice(&tree);
        tx.extend_from_slice(&[0x00, 0x00, 0x00]); // height, 0 tokens, 0 registers
        tx
    }

    /// Decode `bytes` as a transaction on a thread with `stack` bytes of stack.
    /// An overflow aborts the whole test process, which is the loud failure
    /// this is meant to produce.
    fn decode_on_stack(bytes: Vec<u8>, stack: usize) -> Result<(), ReadError> {
        std::thread::Builder::new()
            .stack_size(stack)
            .spawn(move || {
                let mut r = VlqReader::new(&bytes);
                read_transaction(&mut r).map(|_| ())
            })
            .expect("spawn decode thread")
            .join()
            .expect("decode thread panicked")
    }

    // ----- guard -----

    /// The deepest descent a peer can force: a chain far past the budget, which
    /// the decoder follows until the shared depth limit stops it at 110. It must
    /// be rejected, and it must fit in HALF the floor — so a change that makes
    /// frames grow fails here, with the floor itself still intact, instead of
    /// eroding the margin unseen.
    #[test]
    fn worst_case_descent_fits_half_the_decode_stack_floor() {
        let err = decode_on_stack(nested_box_transaction(400), DECODE_THREAD_STACK_BYTES / 2)
            .expect_err("a 400-level nested box chain is past the depth budget");
        assert!(
            matches!(err, ReadError::DepthLimitExceeded { max: 110 }),
            "the shared depth budget must be what stops it, got {err:?}"
        );
    }

    /// The deepest chain that still decodes structurally inside the 4 KiB
    /// proposition window. Legal input a peer may send, so it too must fit in
    /// half the floor.
    #[test]
    fn deepest_accepted_chain_fits_half_the_decode_stack_floor() {
        decode_on_stack(nested_box_transaction(97), DECODE_THREAD_STACK_BYTES / 2)
            .expect("a 97-level chain fits the proposition window and must decode");
    }
}
