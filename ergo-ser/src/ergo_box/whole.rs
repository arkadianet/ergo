//! Whole-[`ErgoBox`] codec (standalone mode), `box_id` scratch helper, and
//! the vector-assisted [`parse_ergo_box_bytes`] parser for boxes carrying
//! non-size-delimited ErgoTrees.

use ergo_primitives::digest::{blake2b256, Digest32, ModifierId};
use ergo_primitives::reader::{ReadError, VlqReader};
use ergo_primitives::writer::VlqWriter;

use crate::ergo_tree::read_ergo_tree;
use crate::error::WriteError;
use crate::register::read_registers;
use crate::token::{Token, TokenId};

use super::candidate::{read_ergo_box_candidate, write_ergo_box_candidate};
use super::{ErgoBox, ErgoBoxCandidate};

/// Serialize a full ErgoBox (standalone mode).
pub fn write_ergo_box(w: &mut VlqWriter, b: &ErgoBox) -> Result<(), WriteError> {
    write_ergo_box_candidate(w, &b.candidate)?;
    w.put_bytes(b.transaction_id.as_bytes());
    w.put_u16(b.index);
    Ok(())
}

/// Read a full ErgoBox (standalone mode).
///
/// Works correctly when the ErgoTree is size-delimited. For non-size-delimited
/// trees, use `parse_ergo_box_bytes` (which requires the caller to supply the
/// exact ErgoTree bytes so the parser can locate the tree/body boundary).
pub fn read_ergo_box(r: &mut VlqReader) -> Result<ErgoBox, ReadError> {
    let candidate = read_ergo_box_candidate(r)?;
    let transaction_id = ModifierId::from_bytes(r.get_array::<32>()?);
    let index = r.get_u16()?;
    Ok(ErgoBox {
        candidate,
        transaction_id,
        index,
    })
}

/// Serialize a full ErgoBox and return the bytes.
pub fn serialize_ergo_box(b: &ErgoBox) -> Result<Vec<u8>, WriteError> {
    let mut w = VlqWriter::new();
    write_ergo_box(&mut w, b)?;
    Ok(w.result())
}

/// Self-cleaning scratch variant of `ErgoBox::box_id`. Clears `w` first, writes
/// the canonical box bytes into it, hashes them, returns the digest. Leaves
/// `w` containing the hashed bytes (caller may inspect via `as_slice()` before
/// the next emit).
///
/// Used by the indexer apply path to reuse a single long-lived `VlqWriter`
/// across many box-id computations without per-call `Vec<u8>` allocations.
/// Byte-identical to `b.box_id()` modulo writer state.
pub fn box_id_with(w: &mut VlqWriter, b: &ErgoBox) -> Result<Digest32, WriteError> {
    w.clear();
    write_ergo_box(w, b)?;
    Ok(blake2b256(w.as_slice()))
}

/// Vector-assisted ErgoBox parser: requires the caller to supply the exact
/// ErgoTree bytes so the parser can locate the tree/body boundary.
///
/// This is NOT an independent streaming parser. For non-size-delimited
/// ErgoTrees, a true streaming parser would need opcode-level body
/// parsing to discover the tree boundary; that's not implemented here.
/// Size-delimited trees can be parsed independently via
/// `read_ergo_box`.
pub fn parse_ergo_box_bytes(
    box_bytes: &[u8],
    ergo_tree_bytes: &[u8],
) -> Result<ErgoBox, ReadError> {
    let mut r = VlqReader::new(box_bytes);
    let value = r.get_u64()?;

    // Read the raw tree bytes directly (we know their length)
    let tree_data = r.get_bytes(ergo_tree_bytes.len())?;
    if tree_data != ergo_tree_bytes {
        return Err(ReadError::InvalidData(
            "ergoTree bytes in box do not match provided tree bytes".into(),
        ));
    }

    // Parse the tree structure from the known bytes
    let mut tree_reader = VlqReader::new(ergo_tree_bytes);
    let ergo_tree = read_ergo_tree(&mut tree_reader)?;
    // `read_ergo_tree` can finish before `ergo_tree_bytes` is exhausted. If the
    // caller supplied more bytes than the tree actually occupies, the surplus
    // (box-tail bytes) would be silently retained as `ergo_tree_bytes` while the
    // parsed `ergo_tree` covers only the prefix — desyncing the raw and parsed
    // tree and shifting every subsequent field. Reject trailing content, matching
    // the box-leftover guard below.
    if !tree_reader.is_empty() {
        return Err(ReadError::InvalidData(format!(
            "{} trailing bytes after ergoTree in supplied tree bytes",
            tree_reader.remaining()
        )));
    }
    crate::ergo_tree::check_tree_version_supported(&ergo_tree)?;
    crate::ergo_tree::check_header_size_bit(&ergo_tree)?;
    crate::ergo_tree::check_resolvable_methods(&ergo_tree)?;
    crate::ergo_tree::check_sigma_prop_root(&ergo_tree)?;

    let creation_height = r.get_u32_exact()?;
    let token_count = r.get_u8()? as usize;
    let mut tokens = Vec::with_capacity(token_count);
    for _ in 0..token_count {
        let token_id = TokenId::from_bytes(r.get_array::<32>()?);
        let amount = r.get_u64()?;
        tokens.push(Token { token_id, amount });
    }
    let reg_start = r.position();
    let additional_registers = read_registers(&mut r)?;
    let reg_end = r.position();
    let register_bytes = r.data_slice(reg_start, reg_end).to_vec();
    let transaction_id = ModifierId::from_bytes(r.get_array::<32>()?);
    let index = r.get_u16()?;

    if !r.is_empty() {
        return Err(ReadError::InvalidData(format!(
            "{} leftover bytes after parsing ErgoBox",
            r.remaining()
        )));
    }

    Ok(ErgoBox {
        candidate: ErgoBoxCandidate {
            value,
            ergo_tree,
            ergo_tree_bytes: ergo_tree_bytes.to_vec(),
            creation_height,
            tokens,
            additional_registers,
            register_bytes,
        },
        transaction_id,
        index,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ergo_tree::ErgoTree;
    use crate::opcode::Expr;
    use crate::register::AdditionalRegisters;
    use crate::sigma_type::SigmaType;
    use crate::sigma_value::SigmaValue;

    // ----- helpers -----

    fn size_delimited_tree() -> ErgoTree {
        ErgoTree {
            version: 0,
            has_size: true,
            constant_segregation: false,
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

    fn make_candidate(tree: &ErgoTree) -> ErgoBoxCandidate {
        ErgoBoxCandidate::new(
            1_000_000_000,
            tree.clone(),
            500_000,
            vec![],
            AdditionalRegisters::empty(),
        )
        .unwrap()
    }

    fn make_token_id(fill: u8) -> TokenId {
        TokenId::from_bytes([fill; 32])
    }

    // ----- round-trips -----

    #[test]
    fn ergo_box_roundtrip() {
        let tree = size_delimited_tree();
        let ergo_box = ErgoBox {
            candidate: ErgoBoxCandidate::new(
                1_000_000,
                tree,
                100,
                vec![Token {
                    token_id: make_token_id(0x01),
                    amount: 500,
                }],
                AdditionalRegisters::empty(),
            )
            .unwrap(),
            transaction_id: ModifierId::from_bytes([0xDE; 32]),
            index: 0,
        };
        let mut w = VlqWriter::new();
        write_ergo_box(&mut w, &ergo_box).unwrap();
        let data = w.result();
        let mut r = VlqReader::new(&data);
        let decoded = read_ergo_box(&mut r).unwrap();
        assert!(r.is_empty(), "leftover bytes");
        assert_eq!(decoded, ergo_box);
    }

    #[test]
    fn box_id_is_blake2b256_of_serialized_bytes() {
        let tree = size_delimited_tree();
        let ergo_box = ErgoBox {
            candidate: ErgoBoxCandidate::new(
                42_000_000,
                tree,
                12345,
                vec![],
                AdditionalRegisters::empty(),
            )
            .unwrap(),
            transaction_id: ModifierId::from_bytes([0xAB; 32]),
            index: 3,
        };
        let serialized = serialize_ergo_box(&ergo_box).unwrap();
        let expected_id = blake2b256(&serialized);
        assert_eq!(ergo_box.box_id().unwrap(), expected_id);
    }

    #[test]
    fn box_id_with_clears_then_matches_box_id() {
        // box_id_with must clear pre-existing writer state and produce the same
        // digest as ErgoBox::box_id(). Reuses the same writer across two boxes
        // to prove the second call's clear() purges the first call's bytes.
        let tree = size_delimited_tree();
        let box_a = ErgoBox {
            candidate: make_candidate(&tree),
            transaction_id: ModifierId::from_bytes([0x10; 32]),
            index: 0,
        };
        let box_b = ErgoBox {
            candidate: ErgoBoxCandidate::new(
                999_999_999,
                tree.clone(),
                1234,
                vec![Token {
                    token_id: make_token_id(0x77),
                    amount: 42,
                }],
                AdditionalRegisters::empty(),
            )
            .unwrap(),
            transaction_id: ModifierId::from_bytes([0x20; 32]),
            index: 7,
        };

        let mut w = VlqWriter::new();
        // Pre-fill with junk to verify clear() runs.
        w.put_bytes(&[0xEE; 100]);

        let id_a = box_id_with(&mut w, &box_a).unwrap();
        assert_eq!(id_a, box_a.box_id().unwrap());
        // Writer holds box_a bytes after the call.
        assert_eq!(w.as_slice(), serialize_ergo_box(&box_a).unwrap().as_slice());

        // Reuse the same writer (still full of box_a bytes) for box_b.
        let id_b = box_id_with(&mut w, &box_b).unwrap();
        assert_eq!(id_b, box_b.box_id().unwrap());
        assert_eq!(w.as_slice(), serialize_ergo_box(&box_b).unwrap().as_slice());

        assert_ne!(id_a, id_b);
    }

    // ----- oracle parity -----

    /// Test box_id computation by constructing boxes from explorer JSON data
    /// (value, ergoTree, creationHeight, tokens, registers, txId, index)
    /// rather than from raw serialized bytes. This mirrors the block validation
    /// code path where we parse a transaction's indexed outputs and then compute
    /// box_id = blake2b256(serialize_ergo_box(candidate + txId + index)).
    #[test]
    fn box_id_from_explorer_data_block_678924() {
        use crate::ergo_tree::read_ergo_tree;

        // Helper: construct ErgoBoxCandidate from explorer fields
        fn make_candidate(
            value: u64,
            ergo_tree_hex: &str,
            creation_height: u32,
            token_pairs: &[(&str, u64)], // (token_id_hex, amount)
            register_hexes: &[&str],     // raw hex for each register (R4, R5, ...)
        ) -> ErgoBoxCandidate {
            let ergo_tree_bytes = hex::decode(ergo_tree_hex).unwrap();
            let mut tree_reader = VlqReader::new(&ergo_tree_bytes);
            let ergo_tree = read_ergo_tree(&mut tree_reader).unwrap();

            let tokens: Vec<Token> = token_pairs
                .iter()
                .map(|(id_hex, amount)| {
                    let id_bytes: [u8; 32] = hex::decode(id_hex).unwrap().try_into().unwrap();
                    Token {
                        token_id: TokenId::from_bytes(id_bytes),
                        amount: *amount,
                    }
                })
                .collect();

            // Build register_bytes: count + concatenated raw register bytes
            let mut reg_bytes = Vec::new();
            reg_bytes.push(register_hexes.len() as u8);
            for reg_hex in register_hexes {
                reg_bytes.extend(hex::decode(reg_hex).unwrap());
            }

            let mut reg_reader = VlqReader::new(&reg_bytes);
            let additional_registers = crate::register::read_registers(&mut reg_reader).unwrap();

            ErgoBoxCandidate::from_trusted_raw_parts(
                value,
                ergo_tree,
                ergo_tree_bytes,
                creation_height,
                tokens,
                additional_registers,
                reg_bytes,
            )
        }

        // --- Case 1: Coinbase output, no tokens, no registers, index 0 ---
        {
            let candidate = make_candidate(
                47617350000000000,
                "101004020e36100204a00b08cd0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ea02d192a39a8cc7a7017300730110010204020404040004c0fd4f05808c82f5f6030580b8c9e5ae040580f882ad16040204c0944004c0f407040004000580f882ad16d19683030191a38cc7a7019683020193c2b2a57300007473017302830108cdeeac93a38cc7b2a573030001978302019683040193b1a5730493c2a7c2b2a573050093958fa3730673079973089c73097e9a730a9d99a3730b730c0599c1a7c1b2a5730d00938cc7b2a5730e0001a390c1a7730f",
                678924,
                &[],
                &[],
            );
            let tx_id_bytes: [u8; 32] =
                hex::decode("5acd847e625391edfd2ff1e5a7e2d7e9b513de50cec073fd84011916c002e81d")
                    .unwrap()
                    .try_into()
                    .unwrap();
            let ergo_box = ErgoBox {
                candidate,
                transaction_id: ModifierId::from_bytes(tx_id_bytes),
                index: 0,
            };
            let computed = ergo_box.box_id().unwrap();
            let expected =
                hex::decode("670055f9fe47254e57d58d85b1fe6c3638000b1c73f06a4fa310ec83306e47d3")
                    .unwrap();
            assert_eq!(
                computed.as_bytes().as_slice(), expected.as_slice(),
                "case 1 (coinbase, idx=0): box_id mismatch\n  computed: {}\n  expected: 670055f9fe47254e57d58d85b1fe6c3638000b1c73f06a4fa310ec83306e47d3",
                hex::encode(computed.as_bytes()),
            );
        }

        // --- Case 2: Box with 1 token, no registers, index 0 ---
        {
            let candidate = make_candidate(
                2000000,
                "0008cd03704333b53273fd0cbec619124f04ba6019241756745273b3eff792e4d8ffc7c9",
                678922,
                &[(
                    "afd0d6cb61e86d15f2a0adc1e7e23df532ba3ff35f8ba88bed16729cae933032",
                    218,
                )],
                &[],
            );
            let tx_id_bytes: [u8; 32] =
                hex::decode("1f0a2f8ea98099c709c820695e5a57f6c378a0976988b1d89f3a804ba5fdec9a")
                    .unwrap()
                    .try_into()
                    .unwrap();
            let ergo_box = ErgoBox {
                candidate,
                transaction_id: ModifierId::from_bytes(tx_id_bytes),
                index: 0,
            };
            let computed = ergo_box.box_id().unwrap();
            let expected =
                hex::decode("0aec689ba2948cb7e24bc8ae07f935bc8cbddf9129ced58491730eee581df58b")
                    .unwrap();
            assert_eq!(
                computed.as_bytes().as_slice(), expected.as_slice(),
                "case 2 (1 token, idx=0): box_id mismatch\n  computed: {}\n  expected: 0aec689ba2948cb7e24bc8ae07f935bc8cbddf9129ced58491730eee581df58b",
                hex::encode(computed.as_bytes()),
            );
        }

        // --- Case 3: Box with 1 token + 3 registers, index 0 ---
        {
            let candidate = make_candidate(
                1000000,
                "100504000400050004000e20011d3364de07e5a26f0c4eef0852cddb387039a921b7154ef3cab22c6eda887fd803d601b2a5730000d602e4c6a70407d603b2db6501fe730100ea02d1ededededed93e4c672010407720293e4c67201050ec5720391e4c672010605730293c27201c2a793db63087201db6308a7938cb2db63087203730300017304cd7202",
                678922,
                &[("8c27dd9d8a35aac1e3167d58858c0a8b4059b277da790552e37eba22df9b9035", 1)],
                &[
                    "0702725e8878d5198ca7f5853dddf35560ddab05ab0a26adae7e664b84162c9962e5",
                    "0e2066443b6f66e13a2da07d5f8f63d284671fbc996e53117f87d3f332b7c5581ff2",
                    "05aee685ff01",
                ],
            );
            let tx_id_bytes: [u8; 32] =
                hex::decode("544cf7839fc83b0f950a22c553e237f4f7500e086539ed82f15a5cff790e5aa6")
                    .unwrap()
                    .try_into()
                    .unwrap();
            let ergo_box = ErgoBox {
                candidate,
                transaction_id: ModifierId::from_bytes(tx_id_bytes),
                index: 0,
            };
            let computed = ergo_box.box_id().unwrap();
            let expected =
                hex::decode("b2588e41b78088972cdbfc3ab52d2a8c838ef6f687de0ce25ab270735c815881")
                    .unwrap();
            assert_eq!(
                computed.as_bytes().as_slice(), expected.as_slice(),
                "case 3 (1 token + 3 regs, idx=0): box_id mismatch\n  computed: {}\n  expected: b2588e41b78088972cdbfc3ab52d2a8c838ef6f687de0ce25ab270735c815881",
                hex::encode(computed.as_bytes()),
            );
        }

        // --- Case 4: Box at index 1 (tests index encoding) ---
        {
            let candidate = make_candidate(
                66000000000,
                "100204a00b08cd02f5924b14325a1ffa8f95f8c00006118728ce3785a648e8b269820a3d3bdfd40dea02d192a39a8cc7a70173007301",
                678924,
                &[],
                &[],
            );
            let tx_id_bytes: [u8; 32] =
                hex::decode("5acd847e625391edfd2ff1e5a7e2d7e9b513de50cec073fd84011916c002e81d")
                    .unwrap()
                    .try_into()
                    .unwrap();
            let ergo_box = ErgoBox {
                candidate,
                transaction_id: ModifierId::from_bytes(tx_id_bytes),
                index: 1,
            };
            let computed = ergo_box.box_id().unwrap();
            let expected =
                hex::decode("647f05f07f8005862dc11cf97b241a9fb0ba667c92442e5e0e482e9d54f71f8a")
                    .unwrap();
            assert_eq!(
                computed.as_bytes().as_slice(), expected.as_slice(),
                "case 4 (idx=1): box_id mismatch\n  computed: {}\n  expected: 647f05f07f8005862dc11cf97b241a9fb0ba667c92442e5e0e482e9d54f71f8a",
                hex::encode(computed.as_bytes()),
            );
        }

        // --- Case 5: Box at index 2 with 4 tokens (tests multi-token + higher index) ---
        {
            let candidate = make_candidate(
                194896249110,
                "0008cd03fcce43f83bee588675595e706e19b2925cdc0ef0c4f4be840313c145f6976d1e",
                678891,
                &[
                    (
                        "30974274078845f263b4f21787e33cc99e9ec19a17ad85a5bc6da2cca91c5a2e",
                        686559081991,
                    ),
                    (
                        "472c3d4ecaa08fb7392ff041ee2e6af75f4a558810a74b28600549d5392810e8",
                        2000000000,
                    ),
                    (
                        "ef802b475c06189fdbf844153cdc1d449a5ba87cce13d11bb47b5a539f27f12b",
                        10446527567863,
                    ),
                    (
                        "fbbaac7337d051c10fc3da0ccb864f4d32d40027551e1c3ea3ce361f39b91e40",
                        900,
                    ),
                ],
                &[],
            );
            let tx_id_bytes: [u8; 32] =
                hex::decode("afee4e609c10dff8c0b5404625c035988e08ab25fbc75650055fea03b70144be")
                    .unwrap()
                    .try_into()
                    .unwrap();
            let ergo_box = ErgoBox {
                candidate,
                transaction_id: ModifierId::from_bytes(tx_id_bytes),
                index: 1,
            };
            let computed = ergo_box.box_id().unwrap();
            let expected =
                hex::decode("2f0e67e0aa776e1856e41dabc3b2209098b1e64297a773b0fb90838a532b4371")
                    .unwrap();
            assert_eq!(
                computed.as_bytes().as_slice(), expected.as_slice(),
                "case 5 (4 tokens, idx=1): box_id mismatch\n  computed: {}\n  expected: 2f0e67e0aa776e1856e41dabc3b2209098b1e64297a773b0fb90838a532b4371",
                hex::encode(computed.as_bytes()),
            );
        }
    }

    /// Test the DB store round-trip: serialize_ergo_box → read_ergo_box → box_id.
    /// This is the exact path when a box is stored in the AVL tree and later
    /// retrieved as an input. Critical for non-size-delimited ErgoTrees where
    /// read_ergo_box must find the tree boundary from the opcode parser.
    #[test]
    fn store_roundtrip_non_size_delimited_tree() {
        use crate::ergo_tree::read_ergo_tree;

        // Non-size-delimited P2P-address tree (header byte 0x00, no SIZE_FLAG)
        let tree_hex = "0008cd03704333b53273fd0cbec619124f04ba6019241756745273b3eff792e4d8ffc7c9";
        let tree_bytes = hex::decode(tree_hex).unwrap();
        let mut tr = VlqReader::new(&tree_bytes);
        let tree = read_ergo_tree(&mut tr).unwrap();

        let candidate = ErgoBoxCandidate::from_trusted_raw_parts(
            2000000,
            tree,
            tree_bytes,
            678922,
            vec![Token {
                token_id: TokenId::from_bytes(
                    hex::decode("afd0d6cb61e86d15f2a0adc1e7e23df532ba3ff35f8ba88bed16729cae933032")
                        .unwrap()
                        .try_into()
                        .unwrap(),
                ),
                amount: 218,
            }],
            crate::register::AdditionalRegisters::empty(),
            vec![0x00],
        );
        let tx_id: [u8; 32] =
            hex::decode("1f0a2f8ea98099c709c820695e5a57f6c378a0976988b1d89f3a804ba5fdec9a")
                .unwrap()
                .try_into()
                .unwrap();

        let ergo_box = ErgoBox {
            candidate,
            transaction_id: ModifierId::from_bytes(tx_id),
            index: 0,
        };

        let original_id = ergo_box.box_id().unwrap();
        let serialized = serialize_ergo_box(&ergo_box).unwrap();

        // Read back via read_ergo_box (the exact store retrieval path)
        let mut r = VlqReader::new(&serialized);
        let readback =
            read_ergo_box(&mut r).unwrap_or_else(|e| panic!("read_ergo_box failed: {e}"));
        assert!(
            r.is_empty(),
            "leftover bytes after read_ergo_box: {}",
            r.remaining()
        );

        let readback_id = readback.box_id().unwrap();
        assert_eq!(
            original_id,
            readback_id,
            "box_id changed after store roundtrip:\n  original: {}\n  readback: {}",
            hex::encode(original_id.as_bytes()),
            hex::encode(readback_id.as_bytes()),
        );

        // Verify the expected box_id from explorer
        let expected =
            hex::decode("0aec689ba2948cb7e24bc8ae07f935bc8cbddf9129ced58491730eee581df58b")
                .unwrap();
        assert_eq!(
            original_id.as_bytes().as_slice(),
            expected.as_slice(),
            "box_id doesn't match explorer"
        );
    }

    #[test]
    fn mainnet_boxes_roundtrip() {
        #[derive(serde::Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct BoxVector {
            box_id: String,
            bytes: String,
            ergo_tree: String,
        }

        let json_data = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../test-vectors/mainnet/boxes_recent.json"
        ))
        .expect("test vectors file");
        let vectors: Vec<BoxVector> = serde_json::from_str(&json_data).expect("parse JSON");

        for (i, tv) in vectors.iter().enumerate() {
            let original_bytes =
                hex::decode(&tv.bytes).unwrap_or_else(|e| panic!("box {i}: bad hex: {e}"));
            let tree_bytes =
                hex::decode(&tv.ergo_tree).unwrap_or_else(|e| panic!("box {i}: bad tree hex: {e}"));

            // Parse using the known tree bytes for boundary detection
            let ergo_box = parse_ergo_box_bytes(&original_bytes, &tree_bytes)
                .unwrap_or_else(|e| panic!("box {i}: parse failed: {e}"));

            // Re-serialize and check byte-identical
            let reserialized = serialize_ergo_box(&ergo_box).unwrap();
            assert_eq!(
                original_bytes,
                reserialized,
                "box {i}: roundtrip mismatch.\n  original:     {}\n  reserialized: {}",
                hex::encode(&original_bytes),
                hex::encode(&reserialized),
            );

            // Verify box_id = Blake2b256(serialized)
            let computed_id = ergo_box.box_id().unwrap();
            let expected_id =
                hex::decode(&tv.box_id).unwrap_or_else(|e| panic!("box {i}: bad boxId hex: {e}"));
            assert_eq!(
                computed_id.as_bytes().as_slice(),
                expected_id.as_slice(),
                "box {i}: box_id mismatch.\n  computed: {}\n  expected: {}",
                hex::encode(computed_id.as_bytes()),
                tv.box_id,
            );
        }
    }
}
