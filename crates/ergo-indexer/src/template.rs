//! ErgoTree template extraction.
//!
//! An ErgoTree "template" is the tree with constant values replaced by
//! placeholders, allowing boxes to be grouped by contract logic regardless of
//! parameter values.
//!
//! ErgoTree byte format (relevant bits):
//! - Byte 0: header.  If bit 4 (`0x10`) is set, constants are segregated.
//! - Segregated layout: `[header(1)] [nConstants(VLQ)] [constants_data] [body]`
//! - Non-segregated layout: the entire byte sequence *is* the template (constants
//!   are embedded in the body and cannot be stripped without a full sigma parser).
//!
//! When the tree is segregated **and** `nConstants == 0`, stripping the
//! segregation metadata is trivial: the template is the header byte with the
//! segregation flag cleared followed by the remaining body bytes.
//!
//! When `nConstants > 0` we would need a full sigma-type deserialiser to skip
//! each constant; instead we fall back to treating the full bytes as the
//! template.

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};

/// Bit mask for the constant-segregation flag in the ErgoTree header byte.
const CONSTANT_SEGREGATION_FLAG: u8 = 0x10;

/// Extract the template bytes from a serialised ErgoTree.
///
/// - Empty input -> empty output.
/// - Non-segregated tree -> full bytes returned as-is.
/// - Segregated tree with 0 constants -> header (segregation flag cleared) + body.
/// - Segregated tree with >0 constants -> full bytes (fallback; sigma parser
///   would be needed to strip the constants).
pub fn extract_template(ergo_tree_bytes: &[u8]) -> Vec<u8> {
    if ergo_tree_bytes.is_empty() {
        return Vec::new();
    }

    let header = ergo_tree_bytes[0];
    let is_segregated = header & CONSTANT_SEGREGATION_FLAG != 0;

    if !is_segregated {
        return ergo_tree_bytes.to_vec();
    }

    // Segregated tree: try to skip constants.
    if ergo_tree_bytes.len() < 2 {
        // Only header byte, no room for VLQ count -- return as-is.
        return ergo_tree_bytes.to_vec();
    }

    let (n_constants, bytes_read) = read_vlq(&ergo_tree_bytes[1..]);
    let body_start = 1 + bytes_read;

    if n_constants == 0 {
        // No constants to skip -- body starts right after the VLQ count.
        let mut template = Vec::with_capacity(1 + ergo_tree_bytes.len() - body_start);
        template.push(header & !CONSTANT_SEGREGATION_FLAG); // clear segregation flag
        template.extend_from_slice(&ergo_tree_bytes[body_start..]);
        return template;
    }

    // Has constants -- cannot skip without a sigma parser; fall back to full bytes.
    ergo_tree_bytes.to_vec()
}

/// Compute the blake2b-256 hash of the extracted template.
pub fn template_hash(ergo_tree_bytes: &[u8]) -> [u8; 32] {
    let template = extract_template(ergo_tree_bytes);
    blake2b256(&template)
}

// ── helpers ────────────────────────────────────────────────────────

/// Decode an unsigned VLQ (Variable-Length Quantity) integer.
///
/// Returns `(value, bytes_consumed)`.
fn read_vlq(data: &[u8]) -> (u64, usize) {
    let mut result: u64 = 0;
    let mut shift = 0u32;
    let mut pos = 0;
    loop {
        if pos >= data.len() {
            break;
        }
        let byte = data[pos];
        pos += 1;
        result |= ((byte & 0x7F) as u64) << shift;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
    }
    (result, pos)
}

/// Compute the blake2b-256 hash of the given data.
fn blake2b256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2bVar::new(32).expect("valid output size");
    hasher.update(data);
    let mut out = [0u8; 32];
    hasher.finalize_variable(&mut out).expect("correct length");
    out
}

// ── tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_segregated_template_is_full_bytes() {
        // Header byte 0x00 -- no segregation flag set.
        let tree = vec![0x00, 0x08, 0xCD, 0x01, 0x02, 0x03];
        let template = extract_template(&tree);
        assert_eq!(template, tree);
    }

    #[test]
    fn segregated_no_constants_strips_header() {
        // Header byte 0x10 (segregation flag set), VLQ count = 0, body = [0xAA, 0xBB].
        let tree = vec![0x10, 0x00, 0xAA, 0xBB];
        let template = extract_template(&tree);
        // Expected: header with segregation flag cleared (0x00) + body bytes.
        assert_eq!(template, vec![0x00, 0xAA, 0xBB]);
    }

    #[test]
    fn template_hash_deterministic() {
        let tree = vec![0x00, 0x08, 0xCD, 0x01, 0x02, 0x03];
        let h1 = template_hash(&tree);
        let h2 = template_hash(&tree);
        assert_eq!(h1, h2);
        // Hash should be 32 bytes and not all zeros.
        assert_ne!(h1, [0u8; 32]);
    }

    #[test]
    fn empty_tree_handled() {
        let template = extract_template(&[]);
        assert!(template.is_empty());

        let hash = template_hash(&[]);
        // blake2b256 of empty input is a well-known constant; just check it is
        // deterministic and non-zero.
        assert_ne!(hash, [0u8; 32]);
        assert_eq!(hash, template_hash(&[]));
    }
}
