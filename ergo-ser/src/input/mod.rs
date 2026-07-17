//! Transaction-input wire codecs.
//!
//! Split by data type, one file per self-contained codec pair:
//!
//! * `context_extension` — [`ContextExtension`] with the dual
//!   `Map1`-`Map4` / HAMT entry-order encoding and the rule-1019
//!   `CheckV6Type` parse gate.
//! * `data_input` — [`DataInput`], a bare 32-byte box reference.
//! * `unsigned_input` — [`UnsignedInput`], box id + context extension
//!   before signing.
//! * `spending_proof` — [`SpendingProof`] and signed [`Input`],
//!   including the `bytes_to_sign` (zeroed-proof) form.

mod context_extension;
mod data_input;
mod spending_proof;
mod unsigned_input;

pub use context_extension::{
    read_context_extension, split_context_extension_bytes, write_context_extension,
    ContextExtension,
};
pub use data_input::{read_data_input, write_data_input, DataInput};
pub use spending_proof::{
    read_input, read_spending_proof, write_input, write_input_to_sign, write_spending_proof, Input,
    SpendingProof,
};
pub use unsigned_input::{read_unsigned_input, write_unsigned_input, UnsignedInput};
