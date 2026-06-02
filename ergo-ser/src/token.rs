use ergo_primitives::digest::Digest32;
use ergo_primitives::reader::{ReadError, VlqReader};
use ergo_primitives::writer::VlqWriter;

/// 32-byte identifier of an Ergo token. Equal to the `box_id` of the
/// transaction output that minted the token.
pub type TokenId = Digest32;

/// A token plus the amount carried by the holding box.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {
    /// Identifier of the token (mint-time `box_id`).
    pub token_id: TokenId,
    /// Token amount held by the box.
    pub amount: u64,
}

/// Serialize a token in standalone form: 32-byte id followed by a
/// VLQ-`u64` amount. Used outside transaction context (e.g. ergo box
/// candidates that aren't yet attached to a tx).
pub fn write_token(w: &mut VlqWriter, token: &Token) {
    w.put_bytes(token.token_id.as_bytes());
    w.put_u64(token.amount);
}

/// Decode the standalone wire form produced by [`write_token`].
pub fn read_token(r: &mut VlqReader) -> Result<Token, ReadError> {
    let token_id = TokenId::from_bytes(r.get_array::<32>()?);
    let amount = r.get_u64()?;
    Ok(Token { token_id, amount })
}

/// Serialize a token using the per-transaction distinct-token table:
/// VLQ-`u32` index into the table followed by a VLQ-`u64` amount. Used
/// inside `Transaction` outputs, where every distinct `TokenId` is
/// emitted once at the transaction level and outputs reference it by
/// index.
pub fn write_token_indexed(w: &mut VlqWriter, token_id_index: u32, amount: u64) {
    w.put_u32(token_id_index);
    w.put_u64(amount);
}

/// Decode the indexed wire form produced by [`write_token_indexed`].
/// Returns `(token_id_index, amount)` — the caller resolves the index
/// against its transaction-level token table.
pub fn read_token_indexed(r: &mut VlqReader) -> Result<(u32, u64), ReadError> {
    let idx = r.get_u32_exact()?;
    let amount = r.get_u64()?;
    Ok((idx, amount))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- helpers -----

    fn make_token_id(fill: u8) -> TokenId {
        TokenId::from_bytes([fill; 32])
    }

    // ----- round-trips -----

    #[test]
    fn standalone_roundtrip() {
        let token = Token {
            token_id: make_token_id(0xAB),
            amount: 1_000_000,
        };
        let mut w = VlqWriter::new();
        write_token(&mut w, &token);
        let data = w.result();
        let mut r = VlqReader::new(&data);
        let decoded = read_token(&mut r).unwrap();
        assert!(r.is_empty(), "leftover bytes");
        assert_eq!(decoded, token);
    }

    #[test]
    fn standalone_large_amount() {
        let token = Token {
            token_id: make_token_id(0x01),
            amount: u64::MAX,
        };
        let mut w = VlqWriter::new();
        write_token(&mut w, &token);
        let data = w.result();
        let mut r = VlqReader::new(&data);
        let decoded = read_token(&mut r).unwrap();
        assert!(r.is_empty());
        assert_eq!(decoded, token);
    }

    #[test]
    fn standalone_zero_amount() {
        let token = Token {
            token_id: make_token_id(0xFF),
            amount: 0,
        };
        let mut w = VlqWriter::new();
        write_token(&mut w, &token);
        let data = w.result();
        let mut r = VlqReader::new(&data);
        let decoded = read_token(&mut r).unwrap();
        assert!(r.is_empty());
        assert_eq!(decoded, token);
    }

    #[test]
    fn indexed_roundtrip() {
        let idx = 7u32;
        let amount = 999_999_999u64;
        let mut w = VlqWriter::new();
        write_token_indexed(&mut w, idx, amount);
        let data = w.result();
        let mut r = VlqReader::new(&data);
        let (decoded_idx, decoded_amount) = read_token_indexed(&mut r).unwrap();
        assert!(r.is_empty());
        assert_eq!(decoded_idx, idx);
        assert_eq!(decoded_amount, amount);
    }

    #[test]
    fn indexed_zero_index() {
        let mut w = VlqWriter::new();
        write_token_indexed(&mut w, 0, 1);
        let data = w.result();
        let mut r = VlqReader::new(&data);
        let (idx, amount) = read_token_indexed(&mut r).unwrap();
        assert!(r.is_empty());
        assert_eq!(idx, 0);
        assert_eq!(amount, 1);
    }

    #[test]
    fn multiple_standalone_tokens() {
        let tokens = vec![
            Token {
                token_id: make_token_id(0x01),
                amount: 100,
            },
            Token {
                token_id: make_token_id(0x02),
                amount: 200,
            },
            Token {
                token_id: make_token_id(0x03),
                amount: 300,
            },
        ];
        let mut w = VlqWriter::new();
        for t in &tokens {
            write_token(&mut w, t);
        }
        let data = w.result();
        let mut r = VlqReader::new(&data);
        for expected in &tokens {
            let decoded = read_token(&mut r).unwrap();
            assert_eq!(&decoded, expected);
        }
        assert!(r.is_empty());
    }

    #[test]
    fn multiple_indexed_tokens() {
        let entries: Vec<(u32, u64)> = vec![(0, 10), (1, 20), (5, 50)];
        let mut w = VlqWriter::new();
        for &(idx, amount) in &entries {
            write_token_indexed(&mut w, idx, amount);
        }
        let data = w.result();
        let mut r = VlqReader::new(&data);
        for &(exp_idx, exp_amount) in &entries {
            let (idx, amount) = read_token_indexed(&mut r).unwrap();
            assert_eq!(idx, exp_idx);
            assert_eq!(amount, exp_amount);
        }
        assert!(r.is_empty());
    }
}
