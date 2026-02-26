use ergo_types::modifier_id::ModifierId;

/// Context for state validation at a specific point in the blockchain.
pub struct StateContext {
    /// Height of the last applied block.
    pub height: u32,
    /// ID of the last applied block.
    pub last_block_id: ModifierId,
    /// Timestamp of the last applied block (ms since epoch).
    pub last_block_timestamp: u64,
}

impl StateContext {
    pub fn new(height: u32, last_block_id: ModifierId, last_block_timestamp: u64) -> Self {
        Self {
            height,
            last_block_id,
            last_block_timestamp,
        }
    }

    /// Create genesis context (height 0, no previous block).
    pub fn genesis() -> Self {
        Self {
            height: 0,
            last_block_id: ModifierId::GENESIS_PARENT,
            last_block_timestamp: 0,
        }
    }

    /// Advance context to the next block.
    pub fn with_block(&self, block_id: ModifierId, block_height: u32, timestamp: u64) -> Self {
        Self {
            height: block_height,
            last_block_id: block_id,
            last_block_timestamp: timestamp,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn genesis_context() {
        let ctx = StateContext::genesis();
        assert_eq!(ctx.height, 0);
        assert_eq!(ctx.last_block_id, ModifierId([0u8; 32]));
        assert_eq!(ctx.last_block_timestamp, 0);
    }

    #[test]
    fn with_block_advances() {
        let ctx = StateContext::genesis();
        let id = ModifierId([1u8; 32]);
        let next = ctx.with_block(id, 1, 1000);
        assert_eq!(next.height, 1);
        assert_eq!(next.last_block_id, id);
        assert_eq!(next.last_block_timestamp, 1000);
    }

    #[test]
    fn sequential_blocks() {
        let mut ctx = StateContext::genesis();
        for i in 1..=5u32 {
            let id = ModifierId([i as u8; 32]);
            ctx = ctx.with_block(id, i, i as u64 * 1000);
        }
        assert_eq!(ctx.height, 5);
    }
}
