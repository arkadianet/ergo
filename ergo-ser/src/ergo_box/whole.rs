//! Whole-[`ErgoBox`] codec (standalone mode), `box_id` scratch helper, and
//! the vector-assisted [`parse_ergo_box_bytes`] consistency check.

use ergo_primitives::digest::{blake2b256, Digest32, ModifierId};
use ergo_primitives::reader::{ReadError, VlqReader};
use ergo_primitives::writer::VlqWriter;

use crate::ergo_tree::read_ergo_tree;
use crate::error::WriteError;
use crate::register::read_registers;
use crate::token::{Token, TokenId};

use super::candidate::{read_ergo_box_candidate_parts, write_ergo_box_candidate};
use super::{ErgoBox, ErgoBoxCandidate};

/// Serialize a full ErgoBox (standalone mode).
pub fn write_ergo_box(w: &mut VlqWriter, b: &ErgoBox) -> Result<(), WriteError> {
    if (b.candidate.box_serialization_version as i8) < 3 {
        super::write_ergo_box_candidate_versioned(
            w,
            &b.candidate,
            b.candidate.box_serialization_version,
        )?;
    } else {
        write_ergo_box_candidate(w, &b.candidate)?;
    }
    w.put_bytes(b.transaction_id.as_bytes());
    w.put_u16(b.index);
    Ok(())
}

/// Read a full ErgoBox (standalone mode).
///
/// Parses both size-delimited and non-size-delimited proposition trees, then
/// consumes the box's transaction id and output index. A fresh top-level reader
/// begins with an empty binding store. For a box accepted in an enclosing
/// expression, use [`read_accepted_ergo_box`] to retain that reader's context.
pub fn read_ergo_box(r: &mut VlqReader) -> Result<ErgoBox, ReadError> {
    // `ErgoBox.sigmaSerializer.parse` on a fresh reader starts with an empty
    // `valDefTypeStore`, so a `ValUse` its tree does not bind is a
    // `NoSuchElementException` (hard). A box read that starts a top-level
    // reader starts that store here too.
    if r.position() == 0 && r.nesting_depth_base() == 0 {
        return crate::transaction::with_fresh_binding_store(r, read_ergo_box_parts);
    }
    read_ergo_box_parts(r)
}

/// Read the bytes of a box already accepted inside an enclosing parse, such
/// as an `SBox` constant's `OpaqueBoxBytes`.
///
/// Scala keeps that box as the `ErgoBox` it parsed on the enclosing reader,
/// whose tree may use a `ValUse` the enclosing tree bound, and never parses
/// its bytes again. [`read_ergo_box`] is a standalone parse with an empty
/// binding store and would reject such a use, so this read tracks no
/// bindings.
pub fn read_accepted_ergo_box(r: &mut VlqReader) -> Result<ErgoBox, ReadError> {
    read_ergo_box_parts(r)
}

fn read_ergo_box_parts(r: &mut VlqReader) -> Result<ErgoBox, ReadError> {
    let start = r.position();
    let candidate = read_ergo_box_candidate_parts(r)?;
    let transaction_id = ModifierId::from_bytes(r.get_array::<32>()?);
    let index = r.get_u16()?;
    let mut parsed = ErgoBox {
        candidate,
        transaction_id,
        index,
    };
    parsed.remember_received_bytes(r.data_slice(start, r.position()));
    Ok(parsed)
}

/// Serialize a full ErgoBox and return the bytes.
pub fn serialize_ergo_box(b: &ErgoBox) -> Result<Vec<u8>, WriteError> {
    let mut w = VlqWriter::new();
    write_ergo_box(&mut w, b)?;
    Ok(w.result())
}

/// Scratch variant of [`ErgoBox::box_id`]. Clears `w` and serializes canonical
/// bytes when possible. A parsed whole box returns its received cached ID;
/// those canonical scratch bytes can therefore hash to a different ID.
/// If an unchanged received box cannot serialize, its cached ID remains
/// available and the scratch is cleared. Newly sealed or changed boxes still
/// propagate writer failures. Identity matches `b.box_id()`.
pub fn box_id_with(w: &mut VlqWriter, b: &ErgoBox) -> Result<Digest32, WriteError> {
    w.clear();
    if let Err(error) = write_ergo_box(w, b) {
        w.clear();
        return b.received_box_id().ok_or(error);
    }
    Ok(b.received_box_id()
        .unwrap_or_else(|| blake2b256(w.as_slice())))
}

/// Parse a complete box and verify its proposition bytes against a separately
/// supplied encoding. Rejects mismatched proposition bytes and trailing content
/// after either the supplied tree or complete box. [`read_ergo_box`] is the
/// streaming parser when no independent proposition-byte check is needed.
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
    // `r` is this function's own fresh reader — a vector-assisted parse with no
    // caller `VersionContext`, so the gate runs under Scala's default context
    // (activated 1), spelled out rather than looked up.
    crate::ergo_tree::check_tree_version_supported(
        &ergo_tree,
        crate::ergo_tree::DEFAULT_ACTIVATED_SCRIPT_VERSION,
    )?;
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
    let additional_registers = read_registers(&mut r)?;
    // Canonical registers and tree, as every box reader keeps them; see
    // `read_ergo_box_candidate`. The registers serialize under the same default
    // context as the tree gate above, whose ErgoTree version is also 1.
    let mut rw = VlqWriter::new();
    crate::register::write_registers_versioned(
        &mut rw,
        &additional_registers,
        crate::ergo_tree::DEFAULT_ACTIVATED_SCRIPT_VERSION,
    )
    .map_err(|e| ReadError::InvalidData(format!("register re-serialize: {e}")))?;
    let register_bytes = rw.result();
    let canonical_tree_bytes = super::canonical_tree_bytes(&ergo_tree, ergo_tree_bytes);
    let transaction_id = ModifierId::from_bytes(r.get_array::<32>()?);
    let index = r.get_u16()?;

    if !r.is_empty() {
        return Err(ReadError::InvalidData(format!(
            "{} leftover bytes after parsing ErgoBox",
            r.remaining()
        )));
    }

    let mut parsed = ErgoBox {
        candidate: ErgoBoxCandidate {
            value,
            ergo_tree,
            ergo_tree_bytes: ergo_tree_bytes.to_vec(),
            canonical_tree_bytes,
            creation_height,
            tokens,
            additional_registers,
            register_bytes,
            box_serialization_version: crate::ergo_tree::DEFAULT_ACTIVATED_SCRIPT_VERSION,
            received_box_identity: None,
        },
        transaction_id,
        index,
    };
    parsed.remember_received_bytes(box_bytes);
    Ok(parsed)
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

    /// A box keeps the tree bytes it was read from as `propositionBytes`, and is
    /// written with the canonical tree; its parsed whole-box ID retains the
    /// received bytes, unlike a newly sealed candidate. Box vectors from SANTA
    /// `Box.tree_count_wrap` #0-#2 and `Box.tree_parse_acceptance` #2/#3
    /// (https://github.com/mwaddip/santa, MIT); expected bytes and
    /// `propositionBytes` are our own sigma-state 6.0.6 JVM runs of
    /// `ErgoBox.sigmaSerializer` / `ErgoBoxCandidate.serializer`.
    #[test]
    fn box_with_non_canonical_tree_keeps_proposition_bytes_and_writes_canonically() {
        let tail = "0100001d823ee9ea823cc80232a19181efad41d66849c33ed5d0d6c5750b8d60f1d66400";
        for (tree, canonical) in [
            ("1807ffffffff0f08d3", "18030008d3"),
            ("1807808080800808d3", "18030008d3"),
            ("10ffffffff0f08d3", "100008d3"),
            ("00d17f", "00d10101"),
            ("00d180", "00d10100"),
            ("00d1937f80", "00d1938501"),
        ] {
            let bytes = hex::decode(format!("c0843d{tree}{tail}")).unwrap();
            let mut r = VlqReader::new(&bytes).with_activated_script_version(3);
            let b = read_ergo_box(&mut r).unwrap_or_else(|e| panic!("{tree}: {e:?}"));
            assert!(r.is_empty(), "{tree}");
            assert_eq!(hex::encode(b.candidate.ergo_tree_bytes()), tree);
            assert_eq!(
                hex::encode(b.candidate.serialized_ergo_tree_bytes()),
                canonical
            );
            assert_eq!(
                hex::encode(serialize_ergo_box(&b).unwrap()),
                format!("c0843d{canonical}{tail}")
            );
        }
    }

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

    // ----- independently captured received versus newly sealed identity -----

    fn cached_identity_fixture() -> serde_json::Value {
        serde_json::from_str(include_str!(
            "../../../test-vectors/scala/box-cached-identity/cases.json"
        ))
        .unwrap()
    }

    fn captured_whole_box() -> ErgoBox {
        let fixture = cached_identity_fixture();
        let bytes = hex::decode(fixture["cases"][0]["cached"].as_str().unwrap()).unwrap();
        read_ergo_box(&mut VlqReader::new(&bytes)).unwrap()
    }

    #[test]
    fn received_whole_box_id_and_new_sealed_id_match_scala() {
        let fixture = cached_identity_fixture();
        let cases = fixture["cases"].as_array().unwrap();
        assert_eq!(cases.len(), 3);
        for case in cases {
            let bytes = hex::decode(case["cached"].as_str().unwrap()).unwrap();
            let mut streaming = bytes.clone();
            streaming.push(0x42);
            let activation = case["activation"].as_str().unwrap().parse().unwrap();
            let mut reader = VlqReader::new(&streaming).with_activated_script_version(activation);
            let parsed = read_ergo_box(&mut reader).unwrap();
            assert_eq!(
                reader.position(),
                case["consumed"].as_str().unwrap().parse::<usize>().unwrap()
            );
            assert_eq!(
                reader.get_u8().unwrap(),
                0x42,
                "only whole-box bytes enter the received ID"
            );
            assert_eq!(
                hex::encode(parsed.box_id().unwrap().as_bytes()),
                case["id"].as_str().unwrap()
            );
            assert_eq!(
                hex::encode(serialize_ergo_box(&parsed).unwrap()),
                case["serialized"].as_str().unwrap()
            );
            let mut scratch = VlqWriter::new();
            assert_eq!(
                box_id_with(&mut scratch, &parsed).unwrap(),
                parsed.box_id().unwrap()
            );
            assert_eq!(
                hex::encode(scratch.as_slice()),
                case["serialized"].as_str().unwrap()
            );
            let assisted =
                parse_ergo_box_bytes(&bytes, parsed.candidate.ergo_tree_bytes()).unwrap();
            assert_eq!(assisted.box_id().unwrap(), parsed.box_id().unwrap());
            let resealed = ErgoBox::new(
                parsed.candidate.clone(),
                parsed.transaction_id,
                parsed.index,
            );
            assert_eq!(
                hex::encode(resealed.box_id().unwrap().as_bytes()),
                case["reconstructedId"].as_str().unwrap()
            );
            assert_eq!(
                hex::encode(serialize_ergo_box(&resealed).unwrap()),
                case["reconstructedBytes"].as_str().unwrap()
            );
            assert_ne!(
                parsed.candidate, resealed.candidate,
                "identity metadata participates in candidate equality"
            );
        }
    }

    #[test]
    fn checked_raw_candidate_seals_with_canonical_tree_and_registers() {
        let parsed = captured_whole_box();
        let raw = ErgoBoxCandidate::try_from_raw_parts(
            parsed.candidate.value,
            parsed.candidate.ergo_tree().clone(),
            parsed.candidate.ergo_tree_bytes().to_vec(),
            parsed.candidate.creation_height,
            parsed.candidate.tokens.clone(),
            parsed.candidate.additional_registers().clone(),
            parsed.candidate.register_bytes().to_vec(),
        )
        .unwrap();
        assert_eq!(raw.ergo_tree_bytes(), parsed.candidate.ergo_tree_bytes());
        assert_eq!(
            raw.serialized_ergo_tree_bytes(),
            parsed.candidate.serialized_ergo_tree_bytes()
        );
        let sealed = ErgoBox::new(raw, parsed.transaction_id, parsed.index);
        let fixture = cached_identity_fixture();
        assert_eq!(
            hex::encode(sealed.box_id().unwrap().as_bytes()),
            fixture["cases"][0]["reconstructedId"].as_str().unwrap()
        );
    }

    #[test]
    fn checked_raw_registers_use_captured_canonical_serialization() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../test-vectors/scala/evaluated_value_forms.json"
        ))
        .unwrap();
        let prefix = fixture["box_prefix"]["candidate_prefix_hex"]
            .as_str()
            .unwrap();
        for form in fixture["forms"].as_array().unwrap() {
            let Some(expected_id) = form["box_id"].as_str().filter(|id| id.len() == 64) else {
                continue;
            };
            let register = form["register_hex"].as_str().unwrap();
            let bytes = hex::decode(format!("{prefix}{register}")).unwrap();
            let parsed =
                crate::ergo_box::read_ergo_box_candidate(&mut VlqReader::new(&bytes)).unwrap();
            let raw_registers = hex::decode(format!("01{register}")).unwrap();
            let checked = ErgoBoxCandidate::try_from_raw_parts(
                parsed.value,
                parsed.ergo_tree().clone(),
                parsed.ergo_tree_bytes().to_vec(),
                parsed.creation_height,
                parsed.tokens.clone(),
                parsed.additional_registers().clone(),
                raw_registers,
            )
            .unwrap();
            assert_eq!(checked.register_bytes(), parsed.register_bytes());
            let sealed = ErgoBox::new(checked, ModifierId::from_bytes([7; 32]), 3);
            assert_eq!(
                hex::encode(sealed.box_id().unwrap().as_bytes()),
                expected_id,
                "{}",
                form["name"]
            );
        }
    }

    #[test]
    fn received_id_does_not_survive_public_field_changes_or_register_replacement() {
        let parsed = captured_whole_box();
        let received_id = parsed.box_id().unwrap();
        let token = Token {
            token_id: make_token_id(0x77),
            amount: 1,
        };
        let mutations: [fn(&mut ErgoBox, &Token); 6] = [
            |b, _| b.candidate.value += 1,
            |b, _| b.candidate.creation_height += 1,
            |b, token| b.candidate.tokens.push(token.clone()),
            |b, _| b.transaction_id = ModifierId::from_bytes([0x33; 32]),
            |b, _| b.index += 1,
            |b, _| {
                b.candidate
                    .replace_additional_registers(AdditionalRegisters::empty())
                    .unwrap()
            },
        ];
        for mutate in mutations {
            let mut changed = parsed.clone();
            mutate(&mut changed, &token);
            let expected = blake2b256(&serialize_ergo_box(&changed).unwrap());
            assert_eq!(changed.box_id().unwrap(), expected);
            assert_ne!(changed.box_id().unwrap(), received_id);
            assert_eq!(
                box_id_with(&mut VlqWriter::new(), &changed).unwrap(),
                expected
            );
        }
        for (tx, index) in [
            (ModifierId::from_bytes([0x44; 32]), parsed.index),
            (parsed.transaction_id, parsed.index + 1),
        ] {
            let resealed = ErgoBox::new(parsed.candidate.clone(), tx, index);
            assert_eq!(
                resealed.box_id().unwrap(),
                blake2b256(&serialize_ergo_box(&resealed).unwrap())
            );
            assert_ne!(resealed.box_id().unwrap(), received_id);
        }
    }

    #[test]
    fn stale_received_metadata_cannot_hide_writer_failure() {
        let mut changed = captured_whole_box();
        changed.candidate.tokens = vec![
            Token {
                token_id: make_token_id(0x77),
                amount: 1
            };
            256
        ];
        assert!(
            changed.box_id().is_err(),
            "changed box must use the writer's existing token-count bound"
        );
        let mut writer = VlqWriter::new();
        assert!(box_id_with(&mut writer, &changed).is_err());
        assert!(
            writer.as_slice().is_empty(),
            "failed scratch writer is cleared"
        );
    }
}
