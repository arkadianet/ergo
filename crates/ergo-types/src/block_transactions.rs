use crate::modifier_id::ModifierId;

/// Maximum number of transactions allowed in a single block.
///
/// Matches Scala's `BlockTransactionsSerializer.MaxTransactionsInBlock = 10000000`.
/// This value is used as the sentinel threshold for detecting v2+ block version
/// encoding: if the first VLQ value > 10,000,000 then it encodes block version,
/// otherwise it is the tx count for a v1 block.
pub const MAX_TRANSACTIONS_IN_BLOCK: u32 = 10_000_000;

/// The transactions section of a block, containing the serialized
/// transaction data along with block version information.
///
/// Corresponds to `BlockTransactions` (modifier type ID 102) in the Scala Ergo node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockTransactions {
    /// The ID of the header these transactions belong to.
    pub header_id: ModifierId,
    /// Block version byte (determines serialization format).
    pub block_version: u8,
    /// Each inner Vec contains the serialized bytes of a single transaction.
    pub tx_bytes: Vec<Vec<u8>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn max_transactions_in_block_constant() {
        assert_eq!(MAX_TRANSACTIONS_IN_BLOCK, 10_000_000);
    }

    #[test]
    fn basic_construction() {
        let tx1 = vec![0x01, 0x02, 0x03];
        let tx2 = vec![0x04, 0x05];
        let bt = BlockTransactions {
            header_id: ModifierId([0xdd; 32]),
            block_version: 2,
            tx_bytes: vec![tx1.clone(), tx2.clone()],
        };
        assert_eq!(bt.header_id, ModifierId([0xdd; 32]));
        assert_eq!(bt.block_version, 2);
        assert_eq!(bt.tx_bytes.len(), 2);
        assert_eq!(bt.tx_bytes[0], tx1);
        assert_eq!(bt.tx_bytes[1], tx2);
    }

    #[test]
    fn empty_block_transactions() {
        let bt = BlockTransactions {
            header_id: ModifierId([0x00; 32]),
            block_version: 1,
            tx_bytes: Vec::new(),
        };
        assert!(bt.tx_bytes.is_empty());
    }

    #[test]
    fn block_transactions_clone_and_eq() {
        let bt = BlockTransactions {
            header_id: ModifierId([0xee; 32]),
            block_version: 3,
            tx_bytes: vec![vec![0xff]],
        };
        let cloned = bt.clone();
        assert_eq!(bt, cloned);
    }
}
