//! Channel types for the block processor thread.
//!
//! [`ProcessorCommand`] flows event-loop → processor.
//! [`ProcessorEvent`] flows processor → event-loop.

use crate::connection_pool::PeerId;
use ergo_types::header::Header;
use ergo_types::modifier_id::ModifierId;

/// Bounded channel capacity for both command and event channels.
pub const CHANNEL_CAPACITY: usize = 256;

// ---------------------------------------------------------------------------
// Commands: event loop → processor
// ---------------------------------------------------------------------------

/// A command sent from the event loop to the block-processor thread.
#[derive(Debug, Clone)]
pub enum ProcessorCommand {
    /// Store a raw modifier (header bytes, block body section, etc.).
    StoreModifier {
        /// Modifier type discriminant (101 = Header, 102 = BlockTransactions, …).
        type_id: u8,
        /// Unique modifier identifier.
        modifier_id: ModifierId,
        /// Serialized modifier bytes.
        data: Vec<u8>,
        /// The peer that delivered this modifier, if known.
        peer_hint: Option<PeerId>,
    },

    /// Store a header that has already been parsed and PoW-validated.
    StorePrevalidatedHeader {
        /// Unique modifier identifier.
        modifier_id: ModifierId,
        /// The parsed header (boxed to keep enum size small).
        header: Box<Header>,
        /// The peer that delivered this modifier, if known.
        peer_hint: Option<PeerId>,
    },

    /// Trigger a cache drain — attempt to apply cached modifiers.
    ApplyFromCache,

    /// Graceful shutdown request.
    Shutdown,
}

// ---------------------------------------------------------------------------
// Events: processor → event loop
// ---------------------------------------------------------------------------

/// An event sent from the block-processor thread back to the event loop.
#[derive(Debug, Clone)]
pub enum ProcessorEvent {
    /// One or more headers were successfully stored/applied.
    HeadersApplied {
        /// IDs of the newly applied headers.
        new_header_ids: Vec<ModifierId>,
        /// Additional modifier IDs that should be downloaded.
        to_download: Vec<ModifierId>,
    },

    /// A full block was validated and applied to state.
    BlockApplied {
        /// Header ID of the applied block.
        header_id: ModifierId,
        /// Block height.
        height: u32,
    },

    /// A modifier was stored in the out-of-order cache.
    ModifierCached {
        /// Modifier type discriminant.
        type_id: u8,
        /// Unique modifier identifier.
        modifier_id: ModifierId,
    },

    /// Validation of a modifier failed.
    ValidationFailed {
        /// Unique modifier identifier.
        modifier_id: ModifierId,
        /// The peer that sent the modifier, for penalty dispatch.
        peer_hint: Option<PeerId>,
        /// Human-readable error description.
        error: String,
    },

    /// Periodic snapshot of processor state for the event loop.
    StateUpdate {
        /// Current best headers-only height.
        headers_height: u32,
        /// Current best full-block height.
        full_height: u32,
        /// Best header ID, if any.
        best_header_id: Option<ModifierId>,
        /// Best full-block header ID, if any.
        best_full_id: Option<ModifierId>,
        /// State root digest.
        state_root: Vec<u8>,
        /// IDs of blocks applied since the last update.
        applied_blocks: Vec<ModifierId>,
        /// If a rollback occurred, the height we rolled back to.
        rollback_height: Option<u32>,
    },
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    /// Both enums must be `Send` so they can cross thread boundaries.
    #[test]
    fn command_and_event_are_send() {
        fn assert_send<T: Send>() {}
        assert_send::<ProcessorCommand>();
        assert_send::<ProcessorEvent>();
    }

    /// Round-trip through `std::sync::mpsc` channels.
    #[test]
    fn channel_round_trip() {
        // Command channel
        let (cmd_tx, cmd_rx) = mpsc::sync_channel::<ProcessorCommand>(CHANNEL_CAPACITY);

        let mid = ModifierId([0xAB; 32]);
        cmd_tx
            .send(ProcessorCommand::StoreModifier {
                type_id: 101,
                modifier_id: mid,
                data: vec![1, 2, 3],
                peer_hint: Some(42),
            })
            .unwrap();
        cmd_tx.send(ProcessorCommand::Shutdown).unwrap();

        match cmd_rx.recv().unwrap() {
            ProcessorCommand::StoreModifier {
                type_id,
                modifier_id,
                data,
                peer_hint,
            } => {
                assert_eq!(type_id, 101);
                assert_eq!(modifier_id, mid);
                assert_eq!(data, vec![1, 2, 3]);
                assert_eq!(peer_hint, Some(42));
            }
            other => panic!("expected StoreModifier, got {:?}", other),
        }

        match cmd_rx.recv().unwrap() {
            ProcessorCommand::Shutdown => {}
            other => panic!("expected Shutdown, got {:?}", other),
        }

        // Event channel
        let (evt_tx, evt_rx) = mpsc::sync_channel::<ProcessorEvent>(CHANNEL_CAPACITY);

        let hid = ModifierId([0xCD; 32]);
        evt_tx
            .send(ProcessorEvent::BlockApplied {
                header_id: hid,
                height: 100,
            })
            .unwrap();

        match evt_rx.recv().unwrap() {
            ProcessorEvent::BlockApplied { header_id, height } => {
                assert_eq!(header_id, hid);
                assert_eq!(height, 100);
            }
            other => panic!("expected BlockApplied, got {:?}", other),
        }
    }
}
