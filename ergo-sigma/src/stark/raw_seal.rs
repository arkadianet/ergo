//! Strict transport + output-prefix decoder for the first EIP-0045 RISC0
//! raw-seal profile. Faithful port of sigmastate
//! `sigma.stark.profile.RawSealV1Decoder` (@9372697).
//!
//! The proof is read directly from its four Ergo collection chunks — a fixed
//! `[65535, 65535, 65535, 26063]` partition (222,668 bytes = 55,667 LE-u32
//! words). Word 32 is the literal outer recursion po2 (18); every other word is
//! a reduced BabyBear residue. Decoding is exact-size, canonical, and
//! fail-closed: any shape/content violation yields a typed [`Failure`], never a
//! panic. Pinned by the raw-seal KATs (real 222,668-byte succinct seals).

use super::babybear;

/// Number of little-endian u32 words in a raw seal.
pub const WORD_COUNT: usize = 55_667;
/// Total transport byte length (`WORD_COUNT * 4`).
pub const BYTE_COUNT: usize = 222_668;
/// Number of transport chunks.
pub const CHUNK_COUNT: usize = 4;
/// The literal outer recursion po2 carried in word 32.
pub const EXPECTED_OUTER_PO2: u32 = 18;
/// Canonical transport partition. The three 65,535-byte boundaries deliberately
/// split little-endian words after three, two, and one bytes respectively.
pub const CANONICAL_CHUNK_LENGTHS: [usize; CHUNK_COUNT] = [65_535, 65_535, 65_535, 26_063];

/// A stable, typed rejection reason. Consensus code branches on these values,
/// never on text. Mirrors `RawSealV1Decoder.Failure` one-for-one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Failure {
    /// The outer chunk collection did not carry exactly four chunks.
    WrongChunkCount(usize),
    /// Chunk `index` had the wrong length.
    WrongChunkLength {
        index: usize,
        expected: usize,
        actual: usize,
    },
    /// The four canonical-length chunks did not sum to `BYTE_COUNT`.
    /// (Structurally unreachable once every chunk length is pinned; retained for
    /// parity with the reference taxonomy.)
    WrongTotalLength { expected: usize, actual: u64 },
    /// The transport ran out of bytes mid-word.
    UnexpectedTransportEof { byte_offset: usize },
    /// Bytes remained after the final word.
    TrailingTransportBytes { byte_offset: usize },
    /// A non-po2 word was `>= BabyBear.P` (unsigned u32 value carried as u64).
    WordNotReduced { word_index: usize, value: u64 },
    /// Word 32 (the outer po2) was not the literal `EXPECTED_OUTER_PO2`.
    WrongOuterPo2 { expected: u32, actual: u64 },
    /// An odd (padding) Poseidon2 root word was not raw zero.
    NonZeroRootPadding { word_index: usize, value: u32 },
    /// A Montgomery-decoded claim halfword exceeded u16.
    ClaimHalfwordOutOfRange { word_index: usize, value: u32 },
}

/// A successfully decoded fixed-size raw seal. Words remain in their wire
/// representation; only the two recursion-output fields are Montgomery-decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decoded {
    /// The 55,667 raw seal words in wire order.
    pub words: Vec<u32>,
    /// The 32-byte inner control root (even words 0..14, Montgomery-decoded).
    pub inner_control_root: [u8; 32],
    /// The 32-byte RISC0 receipt-claim digest (words 16..31 as u16 halfwords).
    pub claim_digest: [u8; 32],
}

/// Decode and validate the exact four-chunk raw-seal transport.
pub fn decode(chunks: &[&[u8]]) -> Result<Decoded, Failure> {
    if chunks.len() != CHUNK_COUNT {
        return Err(Failure::WrongChunkCount(chunks.len()));
    }
    let mut total: u64 = 0;
    for (index, chunk) in chunks.iter().enumerate() {
        let expected = CANONICAL_CHUNK_LENGTHS[index];
        if chunk.len() != expected {
            return Err(Failure::WrongChunkLength {
                index,
                expected,
                actual: chunk.len(),
            });
        }
        total += chunk.len() as u64;
    }
    if total != BYTE_COUNT as u64 {
        return Err(Failure::WrongTotalLength {
            expected: BYTE_COUNT,
            actual: total,
        });
    }

    let mut cursor = ChunkCursor::new(chunks);
    let mut words = vec![0u32; WORD_COUNT];
    for (word_index, slot) in words.iter_mut().enumerate() {
        let mut bytes = [0u8; 4];
        for b in bytes.iter_mut() {
            match cursor.read_unsigned_byte() {
                Some(v) => *b = v,
                None => {
                    return Err(Failure::UnexpectedTransportEof {
                        byte_offset: cursor.byte_offset(),
                    })
                }
            }
        }
        let unsigned_word = u32::from_le_bytes(bytes);
        if word_index == 32 {
            if unsigned_word != EXPECTED_OUTER_PO2 {
                return Err(Failure::WrongOuterPo2 {
                    expected: EXPECTED_OUTER_PO2,
                    actual: unsigned_word as u64,
                });
            }
        } else if unsigned_word >= babybear::P {
            return Err(Failure::WordNotReduced {
                word_index,
                value: unsigned_word as u64,
            });
        }
        *slot = unsigned_word;
    }
    if !cursor.at_end() {
        return Err(Failure::TrailingTransportBytes {
            byte_offset: cursor.byte_offset(),
        });
    }

    // Inner control root: even words 0..14 carry the root; odd words are padding
    // and must be raw zero.
    let mut inner_control_root = [0u8; 32];
    for root_word in 0..8 {
        let even_index = root_word * 2;
        let padding_index = even_index + 1;
        if words[padding_index] != 0 {
            return Err(Failure::NonZeroRootPadding {
                word_index: padding_index,
                value: words[padding_index],
            });
        }
        let decoded = babybear::from_raw(words[even_index]);
        inner_control_root[root_word * 4..root_word * 4 + 4]
            .copy_from_slice(&decoded.to_le_bytes());
    }

    // Claim digest: words 16..31 are Montgomery-decoded u16 halfwords.
    let mut claim_digest = [0u8; 32];
    for claim_word in 0..16 {
        let word_index = claim_word + 16;
        let decoded = babybear::from_raw(words[word_index]);
        if decoded > 0xffff {
            return Err(Failure::ClaimHalfwordOutOfRange {
                word_index,
                value: decoded,
            });
        }
        claim_digest[claim_word * 2..claim_word * 2 + 2]
            .copy_from_slice(&(decoded as u16).to_le_bytes());
    }

    Ok(Decoded {
        words,
        inner_control_root,
        claim_digest,
    })
}

/// Cursor over the four immutable-length chunk references (mirrors the
/// reference `ChunkCursor`: words straddle chunk boundaries).
struct ChunkCursor<'a> {
    chunks: &'a [&'a [u8]],
    chunk_index: usize,
    offset_in_chunk: usize,
    consumed: usize,
}

impl<'a> ChunkCursor<'a> {
    fn new(chunks: &'a [&'a [u8]]) -> Self {
        Self {
            chunks,
            chunk_index: 0,
            offset_in_chunk: 0,
            consumed: 0,
        }
    }

    fn byte_offset(&self) -> usize {
        self.consumed
    }

    fn advance_past_boundary(&mut self) {
        while self.chunk_index < self.chunks.len()
            && self.offset_in_chunk == self.chunks[self.chunk_index].len()
        {
            self.chunk_index += 1;
            self.offset_in_chunk = 0;
        }
    }

    fn read_unsigned_byte(&mut self) -> Option<u8> {
        self.advance_past_boundary();
        if self.chunk_index == self.chunks.len() {
            None
        } else {
            let value = self.chunks[self.chunk_index][self.offset_in_chunk];
            self.offset_in_chunk += 1;
            self.consumed += 1;
            Some(value)
        }
    }

    fn at_end(&mut self) -> bool {
        self.advance_past_boundary();
        self.chunk_index == self.chunks.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- helpers -----

    /// Canonical all-zero word array with the outer po2 set in word 32.
    fn canonical_words() -> Vec<u32> {
        let mut w = vec![0u32; WORD_COUNT];
        w[32] = EXPECTED_OUTER_PO2;
        w
    }

    /// Serialize words to the canonical four-chunk partition (mirror of the
    /// reference spec's `encodeChunks`).
    fn encode_chunks(words: &[u32]) -> Vec<Vec<u8>> {
        assert_eq!(words.len(), WORD_COUNT);
        let mut bytes = Vec::with_capacity(BYTE_COUNT);
        for w in words {
            bytes.extend_from_slice(&w.to_le_bytes());
        }
        let mut chunks = Vec::with_capacity(CHUNK_COUNT);
        let mut offset = 0usize;
        for &len in &CANONICAL_CHUNK_LENGTHS {
            chunks.push(bytes[offset..offset + len].to_vec());
            offset += len;
        }
        chunks
    }

    fn refs(chunks: &[Vec<u8>]) -> Vec<&[u8]> {
        chunks.iter().map(|c| c.as_slice()).collect()
    }

    // ----- oracle parity (real 222,668-byte succinct seals) -----

    #[test]
    fn arkadia_independent_seal_decodes_to_expected_claim() {
        let raw = include_bytes!("../../test-vectors/eip0045/raw-seal-arkadia.bin");
        let expected = include_bytes!("../../test-vectors/eip0045/claim-digest-arkadia.bin");
        assert_eq!(raw.len(), BYTE_COUNT);
        let chunks = split_fixture(raw);
        let decoded = decode(&refs(&chunks)).expect("arkadia seal decodes");
        assert_eq!(decoded.words.len(), WORD_COUNT);
        assert_eq!(decoded.words[32], EXPECTED_OUTER_PO2);
        assert_eq!(&decoded.claim_digest, expected);
    }

    #[test]
    fn direct_po2_15_seal_decodes_to_expected_claim() {
        let raw = include_bytes!("../../test-vectors/eip0045/po2-15-raw-seal.bin");
        let expected = include_bytes!("../../test-vectors/eip0045/po2-15-claim-digest.bin");
        assert_eq!(raw.len(), BYTE_COUNT);
        let chunks = split_fixture(raw);
        let decoded = decode(&refs(&chunks)).expect("direct po2-15 seal decodes");
        assert_eq!(&decoded.claim_digest, expected);
    }

    /// Partition a flat 222,668-byte seal into the canonical four chunks.
    fn split_fixture(raw: &[u8]) -> Vec<Vec<u8>> {
        let mut chunks = Vec::with_capacity(CHUNK_COUNT);
        let mut offset = 0usize;
        for &len in &CANONICAL_CHUNK_LENGTHS {
            chunks.push(raw[offset..offset + len].to_vec());
            offset += len;
        }
        chunks
    }

    // ----- round-trips (word straddles every chunk boundary) -----

    #[test]
    fn words_decode_across_every_split_boundary() {
        let mut words = canonical_words();
        words[16383] = 0x0102_0304;
        words[32767] = 0x1112_1314;
        words[49151] = 0x2122_2324;
        let chunks = encode_chunks(&words);
        assert_eq!(
            chunks.iter().map(|c| c.len()).collect::<Vec<_>>(),
            CANONICAL_CHUNK_LENGTHS
        );
        let decoded = decode(&refs(&chunks)).unwrap();
        assert_eq!(decoded.words[16383], 0x0102_0304);
        assert_eq!(decoded.words[32767], 0x1112_1314);
        assert_eq!(decoded.words[49151], 0x2122_2324);
    }

    #[test]
    fn montgomery_outputs_decode_to_exact_bytes() {
        let mut words = canonical_words();
        let mut expected = [0u8; 32];
        for (i, b) in expected.iter_mut().enumerate() {
            *b = (i + 1) as u8;
        }
        for i in 0..8 {
            let value = u32::from_le_bytes(expected[i * 4..i * 4 + 4].try_into().unwrap());
            words[i * 2] = babybear::to_raw(value);
        }
        for i in 0..16 {
            let value = u16::from_le_bytes(expected[i * 2..i * 2 + 2].try_into().unwrap());
            words[16 + i] = babybear::to_raw(value as u32);
        }
        let decoded = decode(&refs(&encode_chunks(&words))).unwrap();
        assert_eq!(decoded.inner_control_root, expected);
        assert_eq!(decoded.claim_digest, expected);
    }

    // ----- error paths (fail-closed) -----

    #[test]
    fn wrong_chunk_count_is_rejected() {
        let chunks = encode_chunks(&canonical_words());
        let three: Vec<&[u8]> = chunks[..3].iter().map(|c| c.as_slice()).collect();
        assert_eq!(decode(&three), Err(Failure::WrongChunkCount(3)));
        let mut five = refs(&chunks);
        five.push(&[]);
        assert_eq!(decode(&five), Err(Failure::WrongChunkCount(5)));
    }

    #[test]
    fn every_chunk_length_variation_is_rejected() {
        let canonical = encode_chunks(&canonical_words());
        for index in 0..CHUNK_COUNT {
            for delta in [-1i64, 1] {
                let mut changed = canonical.clone();
                let new_len = (CANONICAL_CHUNK_LENGTHS[index] as i64 + delta) as usize;
                changed[index].resize(new_len, 0);
                assert_eq!(
                    decode(&refs(&changed)),
                    Err(Failure::WrongChunkLength {
                        index,
                        expected: CANONICAL_CHUNK_LENGTHS[index],
                        actual: new_len,
                    })
                );
            }
        }
    }

    #[test]
    fn trailing_byte_repartition_is_rejected_at_the_length_gate() {
        // Moving one byte from chunk 0 into chunk 1 keeps the total at 222,668
        // but breaks chunk 0's pinned length — the fixed-partition transport's
        // fail-closed answer to a "trailing byte".
        let mut changed = encode_chunks(&canonical_words());
        let moved = changed[0].pop().unwrap();
        changed[1].push(moved);
        assert_eq!(
            decode(&refs(&changed)),
            Err(Failure::WrongChunkLength {
                index: 0,
                expected: 65_535,
                actual: 65_534,
            })
        );
    }

    #[test]
    fn outer_po2_word_must_be_the_literal_eighteen() {
        let mut words = canonical_words();
        words[32] = 17;
        assert_eq!(
            decode(&refs(&encode_chunks(&words))),
            Err(Failure::WrongOuterPo2 {
                expected: 18,
                actual: 17,
            })
        );
        // A Montgomery-encoded 18 is NOT accepted — word 32 is a literal u32.
        let mut words = canonical_words();
        words[32] = babybear::to_raw(EXPECTED_OUTER_PO2);
        assert_eq!(
            decode(&refs(&encode_chunks(&words))),
            Err(Failure::WrongOuterPo2 {
                expected: 18,
                actual: babybear::to_raw(EXPECTED_OUTER_PO2) as u64,
            })
        );
    }

    #[test]
    fn unreduced_word_is_rejected() {
        let mut words = canonical_words();
        words[33] = babybear::P;
        assert_eq!(
            decode(&refs(&encode_chunks(&words))),
            Err(Failure::WordNotReduced {
                word_index: 33,
                value: babybear::P as u64,
            })
        );
    }

    #[test]
    fn nonzero_root_padding_is_rejected() {
        let mut words = canonical_words();
        words[7] = babybear::to_raw(1);
        assert_eq!(
            decode(&refs(&encode_chunks(&words))),
            Err(Failure::NonZeroRootPadding {
                word_index: 7,
                value: babybear::to_raw(1),
            })
        );
    }

    #[test]
    fn claim_halfword_over_u16_is_rejected() {
        let mut words = canonical_words();
        words[16] = babybear::to_raw(65_536);
        assert_eq!(
            decode(&refs(&encode_chunks(&words))),
            Err(Failure::ClaimHalfwordOutOfRange {
                word_index: 16,
                value: 65_536,
            })
        );
    }
}
