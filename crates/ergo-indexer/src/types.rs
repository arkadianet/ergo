//! Indexed types for the extra-indexer store.
//!
//! Each type has a unique type ID discriminant and binary (big-endian)
//! serialization via `serialize` / `deserialize` methods.

use ergo_types::modifier_id::ModifierId;

use crate::db::IndexerDbError;

// ---------------------------------------------------------------------------
// Type ID constants
// ---------------------------------------------------------------------------

pub const TYPE_ID_INDEXED_BOX: u8 = 5;
pub const TYPE_ID_INDEXED_TX: u8 = 10;
pub const TYPE_ID_INDEXED_ADDRESS: u8 = 15;
pub const TYPE_ID_INDEXED_TEMPLATE: u8 = 20;
pub const TYPE_ID_NUMERIC_TX_INDEX: u8 = 25;
pub const TYPE_ID_NUMERIC_BOX_INDEX: u8 = 30;
pub const TYPE_ID_INDEXED_TOKEN: u8 = 35;

// ---------------------------------------------------------------------------
// Helper: cursor reader
// ---------------------------------------------------------------------------

/// A simple cursor for reading big-endian binary data.
struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    fn read_u8(&mut self) -> Result<u8, IndexerDbError> {
        if self.remaining() < 1 {
            return Err(IndexerDbError::Codec("unexpected end of data (u8)".into()));
        }
        let v = self.data[self.pos];
        self.pos += 1;
        Ok(v)
    }

    fn read_u32(&mut self) -> Result<u32, IndexerDbError> {
        if self.remaining() < 4 {
            return Err(IndexerDbError::Codec("unexpected end of data (u32)".into()));
        }
        let v = u32::from_be_bytes(self.data[self.pos..self.pos + 4].try_into().unwrap());
        self.pos += 4;
        Ok(v)
    }

    fn read_i32(&mut self) -> Result<i32, IndexerDbError> {
        if self.remaining() < 4 {
            return Err(IndexerDbError::Codec("unexpected end of data (i32)".into()));
        }
        let v = i32::from_be_bytes(self.data[self.pos..self.pos + 4].try_into().unwrap());
        self.pos += 4;
        Ok(v)
    }

    fn read_u64(&mut self) -> Result<u64, IndexerDbError> {
        if self.remaining() < 8 {
            return Err(IndexerDbError::Codec("unexpected end of data (u64)".into()));
        }
        let v = u64::from_be_bytes(self.data[self.pos..self.pos + 8].try_into().unwrap());
        self.pos += 8;
        Ok(v)
    }

    fn read_i64(&mut self) -> Result<i64, IndexerDbError> {
        if self.remaining() < 8 {
            return Err(IndexerDbError::Codec("unexpected end of data (i64)".into()));
        }
        let v = i64::from_be_bytes(self.data[self.pos..self.pos + 8].try_into().unwrap());
        self.pos += 8;
        Ok(v)
    }

    fn read_bytes32(&mut self) -> Result<[u8; 32], IndexerDbError> {
        if self.remaining() < 32 {
            return Err(IndexerDbError::Codec(
                "unexpected end of data (32 bytes)".into(),
            ));
        }
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&self.data[self.pos..self.pos + 32]);
        self.pos += 32;
        Ok(buf)
    }

    fn read_bytes(&mut self, len: usize) -> Result<Vec<u8>, IndexerDbError> {
        if self.remaining() < len {
            return Err(IndexerDbError::Codec(format!(
                "unexpected end of data ({len} bytes)"
            )));
        }
        let v = self.data[self.pos..self.pos + len].to_vec();
        self.pos += len;
        Ok(v)
    }

    fn read_modifier_id(&mut self) -> Result<ModifierId, IndexerDbError> {
        Ok(ModifierId(self.read_bytes32()?))
    }

    fn read_bool(&mut self) -> Result<bool, IndexerDbError> {
        let v = self.read_u8()?;
        match v {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(IndexerDbError::Codec(format!("invalid bool value: {v}"))),
        }
    }
}

// ---------------------------------------------------------------------------
// BalanceInfo
// ---------------------------------------------------------------------------

/// Token balance information embedded in `IndexedErgoAddress`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BalanceInfo {
    pub nano_ergs: u64,
    pub tokens: Vec<(ModifierId, u64)>,
}

// ---------------------------------------------------------------------------
// IndexedErgoBox (type 5)
// ---------------------------------------------------------------------------

/// An indexed UTXO box with optional spending info.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexedErgoBox {
    pub box_id: ModifierId,
    pub inclusion_height: u32,
    pub spending_tx_id: Option<ModifierId>,
    pub spending_height: Option<u32>,
    pub ergo_tree: Vec<u8>,
    pub value: u64,
    pub tokens: Vec<(ModifierId, u64)>,
    pub global_index: u64,
}

impl IndexedErgoBox {
    pub fn serialize(&self) -> Vec<u8> {
        let has_spending = self.spending_tx_id.is_some();
        let spending_extra = if has_spending { 32 + 4 } else { 0 };
        let capacity = 1
            + 4
            + 1
            + spending_extra
            + 32
            + 4
            + self.ergo_tree.len()
            + 8
            + 4
            + self.tokens.len() * 40
            + 8;
        let mut buf = Vec::with_capacity(capacity);

        buf.push(TYPE_ID_INDEXED_BOX);
        buf.extend_from_slice(&self.inclusion_height.to_be_bytes());

        if has_spending {
            buf.push(1);
            buf.extend_from_slice(&self.spending_tx_id.unwrap().0);
            buf.extend_from_slice(&self.spending_height.unwrap().to_be_bytes());
        } else {
            buf.push(0);
        }

        buf.extend_from_slice(&self.box_id.0);
        buf.extend_from_slice(&(self.ergo_tree.len() as u32).to_be_bytes());
        buf.extend_from_slice(&self.ergo_tree);
        buf.extend_from_slice(&self.value.to_be_bytes());
        buf.extend_from_slice(&(self.tokens.len() as u32).to_be_bytes());
        for (token_id, amount) in &self.tokens {
            buf.extend_from_slice(&token_id.0);
            buf.extend_from_slice(&amount.to_be_bytes());
        }
        buf.extend_from_slice(&self.global_index.to_be_bytes());
        buf
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, IndexerDbError> {
        let mut c = Cursor::new(data);
        let type_id = c.read_u8()?;
        if type_id != TYPE_ID_INDEXED_BOX {
            return Err(IndexerDbError::Codec(format!(
                "expected type id {TYPE_ID_INDEXED_BOX}, got {type_id}"
            )));
        }
        let inclusion_height = c.read_u32()?;
        let has_spending = c.read_bool()?;
        let (spending_tx_id, spending_height) = if has_spending {
            let tx_id = c.read_modifier_id()?;
            let height = c.read_u32()?;
            (Some(tx_id), Some(height))
        } else {
            (None, None)
        };
        let box_id = c.read_modifier_id()?;
        let ergo_tree_len = c.read_u32()? as usize;
        let ergo_tree = c.read_bytes(ergo_tree_len)?;
        let value = c.read_u64()?;
        let tokens_len = c.read_u32()? as usize;
        let mut tokens = Vec::with_capacity(tokens_len);
        for _ in 0..tokens_len {
            let token_id = c.read_modifier_id()?;
            let amount = c.read_u64()?;
            tokens.push((token_id, amount));
        }
        let global_index = c.read_u64()?;
        Ok(Self {
            box_id,
            inclusion_height,
            spending_tx_id,
            spending_height,
            ergo_tree,
            value,
            tokens,
            global_index,
        })
    }
}

// ---------------------------------------------------------------------------
// IndexedErgoTransaction (type 10)
// ---------------------------------------------------------------------------

/// An indexed transaction with input/output global box indexes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexedErgoTransaction {
    pub tx_id: ModifierId,
    pub index: u32,
    pub height: u32,
    pub size: u32,
    pub global_index: u64,
    pub input_indexes: Vec<u64>,
    pub output_indexes: Vec<u64>,
}

impl IndexedErgoTransaction {
    pub fn serialize(&self) -> Vec<u8> {
        let capacity = 1
            + 32
            + 4
            + 4
            + 4
            + 8
            + 4
            + self.input_indexes.len() * 8
            + 4
            + self.output_indexes.len() * 8;
        let mut buf = Vec::with_capacity(capacity);

        buf.push(TYPE_ID_INDEXED_TX);
        buf.extend_from_slice(&self.tx_id.0);
        buf.extend_from_slice(&self.index.to_be_bytes());
        buf.extend_from_slice(&self.height.to_be_bytes());
        buf.extend_from_slice(&self.size.to_be_bytes());
        buf.extend_from_slice(&self.global_index.to_be_bytes());
        buf.extend_from_slice(&(self.input_indexes.len() as u32).to_be_bytes());
        for &idx in &self.input_indexes {
            buf.extend_from_slice(&idx.to_be_bytes());
        }
        buf.extend_from_slice(&(self.output_indexes.len() as u32).to_be_bytes());
        for &idx in &self.output_indexes {
            buf.extend_from_slice(&idx.to_be_bytes());
        }
        buf
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, IndexerDbError> {
        let mut c = Cursor::new(data);
        let type_id = c.read_u8()?;
        if type_id != TYPE_ID_INDEXED_TX {
            return Err(IndexerDbError::Codec(format!(
                "expected type id {TYPE_ID_INDEXED_TX}, got {type_id}"
            )));
        }
        let tx_id = c.read_modifier_id()?;
        let index = c.read_u32()?;
        let height = c.read_u32()?;
        let size = c.read_u32()?;
        let global_index = c.read_u64()?;
        let input_count = c.read_u32()? as usize;
        let mut input_indexes = Vec::with_capacity(input_count);
        for _ in 0..input_count {
            input_indexes.push(c.read_u64()?);
        }
        let output_count = c.read_u32()? as usize;
        let mut output_indexes = Vec::with_capacity(output_count);
        for _ in 0..output_count {
            output_indexes.push(c.read_u64()?);
        }
        Ok(Self {
            tx_id,
            index,
            height,
            size,
            global_index,
            input_indexes,
            output_indexes,
        })
    }
}

// ---------------------------------------------------------------------------
// IndexedErgoAddress (type 15)
// ---------------------------------------------------------------------------

/// An indexed address keyed by ErgoTree hash, with balance and segment counts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexedErgoAddress {
    pub tree_hash: [u8; 32],
    pub balance: BalanceInfo,
    pub tx_indexes: Vec<i64>,
    pub box_indexes: Vec<i64>,
    pub box_segment_count: u32,
    pub tx_segment_count: u32,
}

impl IndexedErgoAddress {
    pub fn serialize(&self) -> Vec<u8> {
        let capacity = 1
            + 32
            + 8
            + 4
            + self.balance.tokens.len() * 40
            + 4
            + self.tx_indexes.len() * 8
            + 4
            + self.box_indexes.len() * 8
            + 4
            + 4;
        let mut buf = Vec::with_capacity(capacity);

        buf.push(TYPE_ID_INDEXED_ADDRESS);
        buf.extend_from_slice(&self.tree_hash);
        buf.extend_from_slice(&self.balance.nano_ergs.to_be_bytes());
        buf.extend_from_slice(&(self.balance.tokens.len() as u32).to_be_bytes());
        for (token_id, amount) in &self.balance.tokens {
            buf.extend_from_slice(&token_id.0);
            buf.extend_from_slice(&amount.to_be_bytes());
        }
        buf.extend_from_slice(&(self.tx_indexes.len() as u32).to_be_bytes());
        for &idx in &self.tx_indexes {
            buf.extend_from_slice(&idx.to_be_bytes());
        }
        buf.extend_from_slice(&(self.box_indexes.len() as u32).to_be_bytes());
        for &idx in &self.box_indexes {
            buf.extend_from_slice(&idx.to_be_bytes());
        }
        buf.extend_from_slice(&self.box_segment_count.to_be_bytes());
        buf.extend_from_slice(&self.tx_segment_count.to_be_bytes());
        buf
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, IndexerDbError> {
        let mut c = Cursor::new(data);
        let type_id = c.read_u8()?;
        if type_id != TYPE_ID_INDEXED_ADDRESS {
            return Err(IndexerDbError::Codec(format!(
                "expected type id {TYPE_ID_INDEXED_ADDRESS}, got {type_id}"
            )));
        }
        let tree_hash = c.read_bytes32()?;
        let nano_ergs = c.read_u64()?;
        let balance_tokens_len = c.read_u32()? as usize;
        let mut balance_tokens = Vec::with_capacity(balance_tokens_len);
        for _ in 0..balance_tokens_len {
            let token_id = c.read_modifier_id()?;
            let amount = c.read_u64()?;
            balance_tokens.push((token_id, amount));
        }
        let tx_indexes_len = c.read_u32()? as usize;
        let mut tx_indexes = Vec::with_capacity(tx_indexes_len);
        for _ in 0..tx_indexes_len {
            tx_indexes.push(c.read_i64()?);
        }
        let box_indexes_len = c.read_u32()? as usize;
        let mut box_indexes = Vec::with_capacity(box_indexes_len);
        for _ in 0..box_indexes_len {
            box_indexes.push(c.read_i64()?);
        }
        let box_segment_count = c.read_u32()?;
        let tx_segment_count = c.read_u32()?;
        Ok(Self {
            tree_hash,
            balance: BalanceInfo {
                nano_ergs,
                tokens: balance_tokens,
            },
            tx_indexes,
            box_indexes,
            box_segment_count,
            tx_segment_count,
        })
    }
}

// ---------------------------------------------------------------------------
// IndexedContractTemplate (type 20)
// ---------------------------------------------------------------------------

/// An indexed contract template keyed by template hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexedContractTemplate {
    pub template_hash: [u8; 32],
    pub box_indexes: Vec<i64>,
    pub box_segment_count: u32,
}

impl IndexedContractTemplate {
    pub fn serialize(&self) -> Vec<u8> {
        let capacity = 1 + 32 + 4 + self.box_indexes.len() * 8 + 4;
        let mut buf = Vec::with_capacity(capacity);

        buf.push(TYPE_ID_INDEXED_TEMPLATE);
        buf.extend_from_slice(&self.template_hash);
        buf.extend_from_slice(&(self.box_indexes.len() as u32).to_be_bytes());
        for &idx in &self.box_indexes {
            buf.extend_from_slice(&idx.to_be_bytes());
        }
        buf.extend_from_slice(&self.box_segment_count.to_be_bytes());
        buf
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, IndexerDbError> {
        let mut c = Cursor::new(data);
        let type_id = c.read_u8()?;
        if type_id != TYPE_ID_INDEXED_TEMPLATE {
            return Err(IndexerDbError::Codec(format!(
                "expected type id {TYPE_ID_INDEXED_TEMPLATE}, got {type_id}"
            )));
        }
        let template_hash = c.read_bytes32()?;
        let box_indexes_len = c.read_u32()? as usize;
        let mut box_indexes = Vec::with_capacity(box_indexes_len);
        for _ in 0..box_indexes_len {
            box_indexes.push(c.read_i64()?);
        }
        let box_segment_count = c.read_u32()?;
        Ok(Self {
            template_hash,
            box_indexes,
            box_segment_count,
        })
    }
}

// ---------------------------------------------------------------------------
// NumericTxIndex (type 25)
// ---------------------------------------------------------------------------

/// Maps a global transaction number to a transaction ID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NumericTxIndex {
    pub n: u64,
    pub tx_id: ModifierId,
}

impl NumericTxIndex {
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(1 + 8 + 32);
        buf.push(TYPE_ID_NUMERIC_TX_INDEX);
        buf.extend_from_slice(&self.n.to_be_bytes());
        buf.extend_from_slice(&self.tx_id.0);
        buf
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, IndexerDbError> {
        let mut c = Cursor::new(data);
        let type_id = c.read_u8()?;
        if type_id != TYPE_ID_NUMERIC_TX_INDEX {
            return Err(IndexerDbError::Codec(format!(
                "expected type id {TYPE_ID_NUMERIC_TX_INDEX}, got {type_id}"
            )));
        }
        let n = c.read_u64()?;
        let tx_id = c.read_modifier_id()?;
        Ok(Self { n, tx_id })
    }
}

// ---------------------------------------------------------------------------
// NumericBoxIndex (type 30)
// ---------------------------------------------------------------------------

/// Maps a global box number to a box ID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NumericBoxIndex {
    pub n: u64,
    pub box_id: ModifierId,
}

impl NumericBoxIndex {
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(1 + 8 + 32);
        buf.push(TYPE_ID_NUMERIC_BOX_INDEX);
        buf.extend_from_slice(&self.n.to_be_bytes());
        buf.extend_from_slice(&self.box_id.0);
        buf
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, IndexerDbError> {
        let mut c = Cursor::new(data);
        let type_id = c.read_u8()?;
        if type_id != TYPE_ID_NUMERIC_BOX_INDEX {
            return Err(IndexerDbError::Codec(format!(
                "expected type id {TYPE_ID_NUMERIC_BOX_INDEX}, got {type_id}"
            )));
        }
        let n = c.read_u64()?;
        let box_id = c.read_modifier_id()?;
        Ok(Self { n, box_id })
    }
}

// ---------------------------------------------------------------------------
// IndexedToken (type 35)
// ---------------------------------------------------------------------------

/// An indexed token with optional metadata and box index segments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexedToken {
    pub token_id: ModifierId,
    pub box_id: Option<ModifierId>,
    pub amount: Option<u64>,
    pub name: Option<String>,
    pub description: Option<String>,
    pub decimals: Option<i32>,
    pub box_indexes: Vec<i64>,
    pub box_segment_count: u32,
}

impl IndexedToken {
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(128);

        buf.push(TYPE_ID_INDEXED_TOKEN);
        buf.extend_from_slice(&self.token_id.0);

        // has_box_id
        if let Some(ref bid) = self.box_id {
            buf.push(1);
            buf.extend_from_slice(&bid.0);
        } else {
            buf.push(0);
        }

        // has_amount
        if let Some(amt) = self.amount {
            buf.push(1);
            buf.extend_from_slice(&amt.to_be_bytes());
        } else {
            buf.push(0);
        }

        // has_name
        if let Some(ref name) = self.name {
            buf.push(1);
            let name_bytes = name.as_bytes();
            buf.extend_from_slice(&(name_bytes.len() as u32).to_be_bytes());
            buf.extend_from_slice(name_bytes);
        } else {
            buf.push(0);
        }

        // has_description
        if let Some(ref desc) = self.description {
            buf.push(1);
            let desc_bytes = desc.as_bytes();
            buf.extend_from_slice(&(desc_bytes.len() as u32).to_be_bytes());
            buf.extend_from_slice(desc_bytes);
        } else {
            buf.push(0);
        }

        // has_decimals
        if let Some(d) = self.decimals {
            buf.push(1);
            buf.extend_from_slice(&d.to_be_bytes());
        } else {
            buf.push(0);
        }

        // box_indexes
        buf.extend_from_slice(&(self.box_indexes.len() as u32).to_be_bytes());
        for &idx in &self.box_indexes {
            buf.extend_from_slice(&idx.to_be_bytes());
        }
        buf.extend_from_slice(&self.box_segment_count.to_be_bytes());
        buf
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, IndexerDbError> {
        let mut c = Cursor::new(data);
        let type_id = c.read_u8()?;
        if type_id != TYPE_ID_INDEXED_TOKEN {
            return Err(IndexerDbError::Codec(format!(
                "expected type id {TYPE_ID_INDEXED_TOKEN}, got {type_id}"
            )));
        }
        let token_id = c.read_modifier_id()?;

        let box_id = if c.read_bool()? {
            Some(c.read_modifier_id()?)
        } else {
            None
        };

        let amount = if c.read_bool()? {
            Some(c.read_u64()?)
        } else {
            None
        };

        let name =
            if c.read_bool()? {
                let len = c.read_u32()? as usize;
                let bytes = c.read_bytes(len)?;
                Some(String::from_utf8(bytes).map_err(|e| {
                    IndexerDbError::Codec(format!("invalid UTF-8 in token name: {e}"))
                })?)
            } else {
                None
            };

        let description = if c.read_bool()? {
            let len = c.read_u32()? as usize;
            let bytes = c.read_bytes(len)?;
            Some(String::from_utf8(bytes).map_err(|e| {
                IndexerDbError::Codec(format!("invalid UTF-8 in token description: {e}"))
            })?)
        } else {
            None
        };

        let decimals = if c.read_bool()? {
            Some(c.read_i32()?)
        } else {
            None
        };

        let box_indexes_len = c.read_u32()? as usize;
        let mut box_indexes = Vec::with_capacity(box_indexes_len);
        for _ in 0..box_indexes_len {
            box_indexes.push(c.read_i64()?);
        }
        let box_segment_count = c.read_u32()?;

        Ok(Self {
            token_id,
            box_id,
            amount,
            name,
            description,
            decimals,
            box_indexes,
            box_segment_count,
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_modifier_id(byte: u8) -> ModifierId {
        ModifierId([byte; 32])
    }

    #[test]
    fn indexed_box_roundtrip_no_spending() {
        let original = IndexedErgoBox {
            box_id: test_modifier_id(0xAA),
            inclusion_height: 500_000,
            spending_tx_id: None,
            spending_height: None,
            ergo_tree: vec![0x00, 0x08, 0xCD, 0x03],
            value: 1_000_000_000,
            tokens: vec![(test_modifier_id(0xBB), 100), (test_modifier_id(0xCC), 200)],
            global_index: 42,
        };
        let bytes = original.serialize();
        assert_eq!(bytes[0], TYPE_ID_INDEXED_BOX);
        let decoded = IndexedErgoBox::deserialize(&bytes).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn indexed_box_roundtrip_with_spending() {
        let original = IndexedErgoBox {
            box_id: test_modifier_id(0x11),
            inclusion_height: 100_000,
            spending_tx_id: Some(test_modifier_id(0x22)),
            spending_height: Some(100_005),
            ergo_tree: vec![0x01, 0x02, 0x03],
            value: 500_000_000,
            tokens: vec![],
            global_index: 999_999,
        };
        let bytes = original.serialize();
        assert_eq!(bytes[0], TYPE_ID_INDEXED_BOX);
        let decoded = IndexedErgoBox::deserialize(&bytes).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn indexed_tx_roundtrip() {
        let original = IndexedErgoTransaction {
            tx_id: test_modifier_id(0x33),
            index: 5,
            height: 750_000,
            size: 1024,
            global_index: 12_345_678,
            input_indexes: vec![10, 20, 30],
            output_indexes: vec![100, 200],
        };
        let bytes = original.serialize();
        assert_eq!(bytes[0], TYPE_ID_INDEXED_TX);
        let decoded = IndexedErgoTransaction::deserialize(&bytes).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn indexed_address_roundtrip() {
        let original = IndexedErgoAddress {
            tree_hash: [0xDD; 32],
            balance: BalanceInfo {
                nano_ergs: 5_000_000_000,
                tokens: vec![
                    (test_modifier_id(0xEE), 1000),
                    (test_modifier_id(0xFF), 2000),
                ],
            },
            tx_indexes: vec![1, 2, 3, -1],
            box_indexes: vec![10, 20, -5],
            box_segment_count: 2,
            tx_segment_count: 3,
        };
        let bytes = original.serialize();
        assert_eq!(bytes[0], TYPE_ID_INDEXED_ADDRESS);
        let decoded = IndexedErgoAddress::deserialize(&bytes).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn indexed_template_roundtrip() {
        let original = IndexedContractTemplate {
            template_hash: [0x44; 32],
            box_indexes: vec![100, 200, 300],
            box_segment_count: 1,
        };
        let bytes = original.serialize();
        assert_eq!(bytes[0], TYPE_ID_INDEXED_TEMPLATE);
        let decoded = IndexedContractTemplate::deserialize(&bytes).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn numeric_tx_index_roundtrip() {
        let original = NumericTxIndex {
            n: 42_000_000,
            tx_id: test_modifier_id(0x55),
        };
        let bytes = original.serialize();
        assert_eq!(bytes[0], TYPE_ID_NUMERIC_TX_INDEX);
        assert_eq!(bytes.len(), 1 + 8 + 32);
        let decoded = NumericTxIndex::deserialize(&bytes).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn numeric_box_index_roundtrip() {
        let original = NumericBoxIndex {
            n: 99_000_000,
            box_id: test_modifier_id(0x66),
        };
        let bytes = original.serialize();
        assert_eq!(bytes[0], TYPE_ID_NUMERIC_BOX_INDEX);
        assert_eq!(bytes.len(), 1 + 8 + 32);
        let decoded = NumericBoxIndex::deserialize(&bytes).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn indexed_token_roundtrip_all_fields() {
        let original = IndexedToken {
            token_id: test_modifier_id(0x77),
            box_id: Some(test_modifier_id(0x88)),
            amount: Some(1_000_000),
            name: Some("SigUSD".to_string()),
            description: Some("Algorithmic stablecoin on Ergo".to_string()),
            decimals: Some(2),
            box_indexes: vec![10, 20, 30],
            box_segment_count: 1,
        };
        let bytes = original.serialize();
        assert_eq!(bytes[0], TYPE_ID_INDEXED_TOKEN);
        let decoded = IndexedToken::deserialize(&bytes).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn indexed_token_roundtrip_no_optional() {
        let original = IndexedToken {
            token_id: test_modifier_id(0x99),
            box_id: None,
            amount: None,
            name: None,
            description: None,
            decimals: None,
            box_indexes: vec![],
            box_segment_count: 0,
        };
        let bytes = original.serialize();
        assert_eq!(bytes[0], TYPE_ID_INDEXED_TOKEN);
        let decoded = IndexedToken::deserialize(&bytes).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn wrong_type_id_errors() {
        // Serialize a NumericTxIndex but try to deserialize as NumericBoxIndex.
        let tx = NumericTxIndex {
            n: 1,
            tx_id: test_modifier_id(0xAA),
        };
        let bytes = tx.serialize();
        let result = NumericBoxIndex::deserialize(&bytes);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("expected type id"));
    }
}
