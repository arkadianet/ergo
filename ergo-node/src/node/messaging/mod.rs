//! Inbound peer-message dispatcher.
//!
//! [`dispatch::handle_message`] is the action loop's per-frame entry
//! point: per-peer throughput throttle, then one match arm per
//! `message::CODE_*` opcode that deserializes the payload and routes
//! through the appropriate coordinator / executor / mempool-validator
//! path. Returns the action list the runtime then drains via
//! `flush_actions`. The three sizable per-batch arms (`CODE_INV`,
//! `CODE_MODIFIER`, `CODE_PEERS`) are factored into named helpers
//! alongside `handle_message` in [`dispatch`]; the three Mode-2 /
//! NiPoPoW-bootstrap consume-side handlers each get their own
//! submodule ([`manifest`], [`utxo_chunk`], [`popow`]).

mod dispatch;
mod manifest;
mod popow;
mod utxo_chunk;

pub(in crate::node) use dispatch::handle_message;
