//! ErgoTree wire codec.
//!
//! Split by concern (deserialization dominates; writing is trivial):
//!
//! * `mod.rs` — the [`ErgoTree`] struct, [`write_ergo_tree`] /
//!   `write_ergo_tree_body`, and the header/limit constants shared by the
//!   submodules.
//! * `gates.rs` — consensus reject-gate functions the box-script readers
//!   apply after the lenient parse.
//! * `type_infer.rs` — the rule-1001 static type-inference subsystem.
//! * `read.rs` — [`read_ergo_tree`] and the soft-fork wrap machinery
//!   (one continuous decision tree mirroring Scala's `deserializeErgoTree`).
//! * `hash.rs` — indexer-facing tree-hash / template-hash utilities.

use ergo_primitives::writer::VlqWriter;

use crate::error::WriteError;
use crate::opcode::{self, Body};
use crate::sigma_type::SigmaType;
use crate::sigma_value::{write_constant, SigmaValue};

mod gates;
mod hash;
mod read;
#[cfg(test)]
mod tests;
mod type_infer;

pub use gates::{
    check_header_size_bit, check_resolvable_methods, check_sigma_prop_root,
    check_tree_version_supported,
};
pub use hash::{
    template_bytes, template_hash, template_hash_from_bytes, tree_hash_from_bytes,
    TemplateHashError, TreeHashError,
};
pub(crate) use read::read_ergo_tree_tracking_wrap;
pub use read::{read_ergo_tree, read_ergo_tree_with_activated_version};
pub use type_infer::determinable_root_type_of;

const VERSION_MASK: u8 = 0x07;
const SIZE_FLAG: u8 = 0x08;
const CONSTANT_SEGREGATION_FLAG: u8 = 0x10;

/// Soft `Vec::with_capacity` cap for an ErgoTree's segregated-constant list.
/// `parse_body` reads the count via `get_u32_exact`, which only bounds it to
/// i32::MAX — so a hostile tree header claiming `count = i32::MAX` would
/// otherwise reserve multiple GiB before the first constant is read. The Vec
/// still grows on `push`, so a legitimate tree with more constants than this
/// parses unchanged; the cap only bounds the *initial* reservation. It is a
/// soft cap (not the hard reject `skip_ergo_tree` applies to inner,
/// box-size-bounded trees) because `parse_body` is the top-level consensus
/// parse and must not reject a tree the Scala node would accept.
const CONSTANTS_VEC_SOFT_CAP: usize = 4096;

/// Scala `SigmaSerializer.MaxPropositionSize` (`SigmaConstants.MaxPropositionBytes`
/// = 4096). `deserializeErgoTree` bounds the body parse by this position limit —
/// NOT by the tree's declared size, which it uses only for the `UnparsedErgoTree`
/// byte count. So the body is structure-delimited up to this cap.
const MAX_PROPOSITION_BYTES: usize = 4096;

/// Parsed ErgoTree: header byte + optional constants table + parsed
/// body expression.
///
/// The `version` / `has_size` / `constant_segregation` triple is the
/// decomposition of the on-wire header byte:
/// `header = (version & 0x07) | (has_size ? 0x08 : 0) | (cseg ? 0x10 : 0)`.
#[derive(Debug, Clone, PartialEq)]
pub struct ErgoTree {
    /// ErgoTree layout version (low 3 bits of the header byte).
    pub version: u8,
    /// `true` when the header carries a VLQ-`u32` size field that
    /// length-prefixes the body — required for the soft-fork-friendly
    /// path that lets unknown bodies round-trip verbatim.
    pub has_size: bool,
    /// `true` when constants are pulled out into a separate table
    /// referenced by `ConstPlaceholder` opcodes inside the body.
    pub constant_segregation: bool,
    /// Constants table — only populated when `constant_segregation` is set.
    pub constants: Vec<(SigmaType, SigmaValue)>,
    /// Root body expression.
    pub body: Body,
}

/// Serialize an ErgoTree to bytes.
pub fn write_ergo_tree(w: &mut VlqWriter, tree: &ErgoTree) -> Result<(), WriteError> {
    // A soft-fork-wrapped (unparsed) tree re-emits its preserved original bytes
    // verbatim — header + size + body, byte-identical to the wire form — exactly
    // as Scala re-serializes an `UnparsedErgoTree` from its kept `propositionBytes`.
    if let crate::opcode::Expr::Unparsed(raw) = &tree.body {
        w.put_bytes(raw);
        return Ok(());
    }
    let header = (tree.version & VERSION_MASK)
        | if tree.has_size { SIZE_FLAG } else { 0 }
        | if tree.constant_segregation {
            CONSTANT_SEGREGATION_FLAG
        } else {
            0
        };
    w.put_u8(header);

    if tree.has_size {
        let mut inner = VlqWriter::new();
        write_ergo_tree_body(&mut inner, tree)?;
        let inner_bytes = inner.result();
        w.put_u32(inner_bytes.len() as u32);
        w.put_bytes(&inner_bytes);
    } else {
        write_ergo_tree_body(w, tree)?;
    }
    Ok(())
}

fn write_ergo_tree_body(w: &mut VlqWriter, tree: &ErgoTree) -> Result<(), WriteError> {
    if tree.constant_segregation {
        w.put_u32(tree.constants.len() as u32);
        for (tpe, val) in &tree.constants {
            write_constant(w, tpe, val)?;
        }
    }
    opcode::write_body(w, &tree.body, tree.constant_segregation)?;
    Ok(())
}

/// Maximum ErgoTree version we can fully parse and evaluate.
/// Trees with higher versions are accepted without body parsing (soft-fork).
/// Matches Scala's VersionContext.MaxSupportedScriptVersion = 3.
const MAX_SUPPORTED_TREE_VERSION: u8 = 3;
