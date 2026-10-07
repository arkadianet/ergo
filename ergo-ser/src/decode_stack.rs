//! Stack floor for every thread that can deserialize peer-supplied bytes.
//!
//! The shared value depth budget bounds recursion through expressions, box
//! scripts, registers and SigmaBoolean values. Type descriptors have a separate
//! depth cap and can add frames beneath that recursion. A stack floor supplements
//! those guards; it cannot replace them.
//!
//! Tests exercise several deep transaction shapes on half the floor. They are
//! regression checks for the compiled profile and platform, not a proof of the
//! maximum stack consumption across all possible inputs or compiler versions.

/// Stack size, in bytes, for the Tokio runtime's threads (workers and blocking
/// pool), Rayon, startup, mining and indexing threads.
pub const DECODE_THREAD_STACK_BYTES: usize = 8 * 1024 * 1024;

#[cfg(test)]
mod tests {
    use super::DECODE_THREAD_STACK_BYTES;
    use crate::transaction::read_transaction;
    use ergo_primitives::reader::{ReadError, VlqReader};

    // ----- helpers -----

    /// A one-output transaction whose output proposition nests `levels` `SBox`
    /// constants: each level is a size-delimited v0 tree whose body is an
    /// `SBox` constant carrying the next level's box. Every level re-enters the
    /// tree reader through a box, reached through the transaction decoder.
    fn nested_box_transaction(levels: usize) -> Vec<u8> {
        fn box_bytes(tree: &[u8]) -> Vec<u8> {
            let mut b = vec![0x01u8]; // value = 1 nanoErg
            b.extend_from_slice(tree); // proposition
            b.extend_from_slice(&[0x00, 0x00, 0x00]); // height, 0 tokens, 0 registers
            b.extend_from_slice(&[0u8; 32]); // transaction id
            b.push(0x00); // output index: VLQ u16 zero is one byte
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
                read_transaction(&mut r)?;
                assert!(r.is_empty(), "accepted fixture has trailing bytes");
                Ok(())
            })
            .expect("spawn decode thread")
            .join()
            .expect("decode thread panicked")
    }

    // ----- guard -----

    #[test]
    fn value_depth_boundaries_match_captured_scala_verdicts() {
        for line in include_str!("../../test-vectors/scala/sigma/decode_depth.tsv").lines() {
            if line.starts_with('#') || line.is_empty() {
                continue;
            }
            let columns: Vec<_> = line.split_whitespace().collect();
            let bytes = hex::decode(columns[4]).unwrap();
            let mut r = VlqReader::new(&bytes);
            let result = crate::sigma_value::read_constant(&mut r);
            if columns[2] == "ACCEPT" {
                result.unwrap_or_else(|e| panic!("{}: {e:?}", columns[0]));
                assert_eq!(r.position(), columns[3].parse::<usize>().unwrap());
                assert!(r.is_empty(), "{}", columns[0]);
            } else {
                assert!(
                    matches!(result, Err(ReadError::DepthLimitExceeded { max: 110 })),
                    "{}: {result:?}",
                    columns[0]
                );
            }
            assert_eq!(
                r.nesting_depth_base(),
                0,
                "box scope must restore on success and error"
            );
        }
    }

    /// A script chain far past the budget, which
    /// the decoder follows until the shared depth limit stops it at 110. It must
    /// be rejected, and it must fit in HALF the floor — so a change that makes
    /// frames grow fails here, with the floor itself still intact, instead of
    /// eroding the margin unseen.
    #[test]
    fn script_descent_fits_half_the_decode_stack_floor() {
        let err = decode_on_stack(nested_box_transaction(400), DECODE_THREAD_STACK_BYTES / 2)
            .expect_err("a 400-level nested box chain is past the depth budget");
        assert!(
            matches!(err, ReadError::DepthLimitExceeded { max: 110 }),
            "the shared depth budget must be what stops it, got {err:?}"
        );
    }

    /// A deep complete transaction must fit in half the floor too.
    #[test]
    fn accepted_script_chain_fits_half_the_decode_stack_floor() {
        decode_on_stack(nested_box_transaction(53), DECODE_THREAD_STACK_BYTES / 2)
            .expect("a 53-level chain must decode completely");
    }

    /// Every box has a shallow proposition and one SBox register. The enclosing
    /// box level must remain active while that register is being read.
    fn register_transaction(levels: usize, leaf: &[u8]) -> Vec<u8> {
        let mut register = leaf.to_vec();
        for _ in 0..levels {
            let mut next = vec![0x63, 1, 0, 8, 0xd3, 0, 0, 1];
            next.extend_from_slice(&register);
            next.extend_from_slice(&[0; 32]);
            next.push(0); // VLQ output index
            register = next;
        }
        let mut tx = vec![0, 0, 0, 1, 1, 0, 8, 0xd3, 0, 0, 1];
        tx.extend_from_slice(&register);
        tx
    }

    #[test]
    fn register_descent_fits_half_the_decode_stack_floor() {
        // Include the reported deep transaction shapes. Input depth must not
        // turn into call-stack depth after the shared budget is exhausted.
        for levels in [400, 800, 3_000] {
            let err = decode_on_stack(
                register_transaction(levels, &[4, 2]),
                DECODE_THREAD_STACK_BYTES / 2,
            )
            .expect_err("register nesting must consume the shared budget");
            assert!(
                matches!(err, ReadError::DepthLimitExceeded { max: 110 }),
                "{levels}-level register chain must stop at the shared depth limit: {err:?}"
            );
        }
    }

    #[test]
    fn accepted_register_chain_fits_half_the_decode_stack_floor() {
        decode_on_stack(
            register_transaction(53, &[4, 2]),
            DECODE_THREAD_STACK_BYTES / 2,
        )
        .expect("complete register chain within the byte and depth limits");
    }

    #[test]
    fn mixed_register_expression_type_descent_fits_half_the_decode_stack_floor() {
        // At the bottom of 45 boxes, parse 18 unary expressions followed by a
        // 9-layer type descriptor. Types allow 8 recursive calls plus an embedded terminal.
        // An empty outer collection needs no values for its nested element type.
        let mut leaf = vec![0xef; 18]; // LogicalNot
        leaf.extend_from_slice(&[0x0c; 8]); // Coll[...]
        leaf.extend_from_slice(&[0x10, 0]); // Coll[Int], empty outer collection
        let err = decode_on_stack(
            register_transaction(45, &leaf),
            DECODE_THREAD_STACK_BYTES / 2,
        )
        .expect_err("register expressions must be evaluated values");
        assert!(
            matches!(err, ReadError::InvalidData(ref msg) if msg.contains("unsupported expression opcode")),
            "{err:?}"
        );
    }
}
