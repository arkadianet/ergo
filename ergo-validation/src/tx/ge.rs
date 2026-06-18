//! Output-box group-element validation.
//!
//! Scala curve-checks every `GroupElement` while *deserializing* a transaction
//! (ProveDlog/ProveDHTuple, SGroupElement constants/collections, R4-R9
//! registers, SHeader autolykos keys, nested SBox values, input context-
//! extension values), so a transaction carrying an off-curve point or an
//! invalid SEC1 prefix is rejected at deserialize. The node's `ergo-ser` layer
//! is crypto-free and stores point bytes unvalidated, deferring the curve check
//! to spend-eval — which never runs for a freshly-created output. Without this
//! the node would accept such a transaction (and any block carrying it) where
//! the JVM rejects it: an accept-invalid fork.
//!
//! `ergo-ser` collects every group element it reads onto the reader's sideband
//! during the parse (surviving soft-fork wrapping and opaque SBox bodies, which
//! a post-parse AST walk loses). Here we validate that collected set with the
//! JVM-matching [`ergo_sigma::evaluator::validate_group_element`] (`0x00`-lead
//! identity accepted; any other lead must be on-curve).

use crate::error::ValidationError;

/// Curve-check every group element collected during a transaction parse.
pub(crate) fn validate_group_elements(points: &[[u8; 33]]) -> Result<(), ValidationError> {
    for ge in points {
        ergo_sigma::evaluator::validate_group_element(*ge).map_err(|e| {
            ValidationError::Deserialization(format!("invalid group element: {e:?}"))
        })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_primitives::reader::VlqReader;
    use ergo_primitives::writer::VlqWriter;
    use ergo_ser::ergo_box::read_ergo_box_candidate;

    fn hx(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    const G_X: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

    /// Group elements collected while parsing a one-output box whose P2PK script
    /// point is `point_hex` (exercises the ergo-ser record path end to end).
    fn ges_for_p2pk_output(point_hex: &str) -> Vec<[u8; 33]> {
        let mut w = VlqWriter::new();
        w.put_u64(1_000_000);
        w.put_bytes(&hx(&format!("0008cd{point_hex}"))); // P2PK ergoTree
        w.put_u32(0);
        w.put_u8(0); // tokens
        w.put_u8(0); // registers
        let bytes = w.result();
        let mut r = VlqReader::new(&bytes);
        read_ergo_box_candidate(&mut r).expect("parse candidate");
        r.take_group_elements()
    }

    // ----- oracle parity (JVM GroupElementSerializer.parse accept-set) -----

    #[test]
    fn on_curve_point_accepted() {
        let ges = ges_for_p2pk_output(G_X);
        assert_eq!(ges.len(), 1, "P2PK point recorded during parse");
        assert!(validate_group_elements(&ges).is_ok());
    }

    #[test]
    fn identity_point_accepted() {
        let ges = ges_for_p2pk_output(&format!("00{}", "00".repeat(32)));
        assert!(validate_group_elements(&ges).is_ok());
    }

    #[test]
    fn off_curve_point_rejected() {
        let ges = ges_for_p2pk_output(&format!("02{}", "00".repeat(32)));
        assert!(matches!(
            validate_group_elements(&ges),
            Err(ValidationError::Deserialization(_))
        ));
    }

    #[test]
    fn bad_prefix_point_rejected() {
        let ges = ges_for_p2pk_output(&format!("04{}", "00".repeat(32)));
        assert!(validate_group_elements(&ges).is_err());
    }
}
