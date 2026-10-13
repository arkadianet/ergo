#![no_std]
// Vendored code: keep upstream style; correctness and suspicious lints stay on.
#![allow(clippy::style, clippy::complexity, clippy::perf, rustdoc::bare_urls)]
pub mod authenticated_tree_ops;
pub mod batch_avl_prover;
pub mod batch_avl_verifier;
pub mod batch_node;
pub mod operation;
pub mod persistent_batch_avl_prover;
pub mod versioned_avl_storage;

extern crate alloc;
