//! Ergo wallet subsystem — key management, balance tracking, and transaction generation.

pub mod keys;
pub mod keystore;
pub mod scan_logic;
pub mod scan_types;
pub mod tracked_box;
pub mod tx_ops;
pub mod wallet_manager;
pub mod wallet_registry;
pub mod wallet_storage;
