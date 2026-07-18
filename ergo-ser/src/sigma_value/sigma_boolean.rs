//! [`SigmaBoolean`] tree wire codec (Scala `SigmaBooleanSerializer` tag
//! layout) and the shared `MaxTreeDepth` bound on its recursion.

use ergo_primitives::group_element::read_group_element;
use ergo_primitives::reader::{ReadError, VlqReader};
use ergo_primitives::writer::VlqWriter;

use super::SigmaBoolean;
use crate::error::WriteError;

// SigmaPropCodes from sigmastate-interpreter (SigmaPropCodes.scala).
// Computed as LastConstantCode(0x70) + shift.
const PROVE_DLOG: u8 = 0xCD; // 0x70 + 93
const PROVE_DHTUPLE: u8 = 0xCE; // 0x70 + 94
const SIGMA_AND: u8 = 0x96; // 0x70 + 38
const SIGMA_OR: u8 = 0x97; // 0x70 + 39
const SIGMA_THRESHOLD: u8 = 0x98; // 0x70 + 40
const TRIVIAL_PROP_FALSE: u8 = 0xD2; // 0x70 + 98
const TRIVIAL_PROP_TRUE: u8 = 0xD3; // 0x70 + 99

// -- SigmaBoolean tree serialization --

/// Serialize a [`SigmaBoolean`] tree using the Scala
/// `SigmaBooleanSerializer` tag layout: a one-byte node tag (`0xCD`
/// ProveDlog, `0xCE` ProveDHTuple, `0x96` Cand, `0x97` Cor, `0x98`
/// Cthreshold, `0xD2`/`0xD3` trivial false/true) followed by the
/// node-specific payload.
pub fn write_sigma_boolean(w: &mut VlqWriter, sb: &SigmaBoolean) -> Result<(), WriteError> {
    fn check_children_len(len: usize, node: &str) -> Result<(), WriteError> {
        if len > u16::MAX as usize {
            return Err(WriteError::InvalidData(format!(
                "{node} children count too large for Scala wire format: {len} (max 65535)"
            )));
        }
        Ok(())
    }
    match sb {
        SigmaBoolean::TrivialProp(false) => w.put_u8(TRIVIAL_PROP_FALSE),
        SigmaBoolean::TrivialProp(true) => w.put_u8(TRIVIAL_PROP_TRUE),
        SigmaBoolean::ProveDlog(ge) => {
            w.put_u8(PROVE_DLOG);
            w.put_bytes(ge.as_bytes());
        }
        SigmaBoolean::ProveDHTuple { g, h, u, v } => {
            w.put_u8(PROVE_DHTUPLE);
            w.put_bytes(g.as_bytes());
            w.put_bytes(h.as_bytes());
            w.put_bytes(u.as_bytes());
            w.put_bytes(v.as_bytes());
        }
        SigmaBoolean::Cand(children) => {
            check_children_len(children.len(), "Cand")?;
            w.put_u8(SIGMA_AND);
            w.put_u16(children.len() as u16);
            for child in children {
                write_sigma_boolean(w, child)?;
            }
        }
        SigmaBoolean::Cor(children) => {
            check_children_len(children.len(), "Cor")?;
            w.put_u8(SIGMA_OR);
            w.put_u16(children.len() as u16);
            for child in children {
                write_sigma_boolean(w, child)?;
            }
        }
        SigmaBoolean::Cthreshold { k, children } => {
            check_children_len(children.len(), "Cthreshold")?;
            w.put_u8(SIGMA_THRESHOLD);
            w.put_u16(*k);
            w.put_u16(children.len() as u16);
            for child in children {
                write_sigma_boolean(w, child)?;
            }
        }
    }
    Ok(())
}

/// Scala bounds nested value/`SigmaBoolean` deserialization at
/// `SigmaConstants.MaxTreeDepth` (= 110) via the shared reader level
/// (`CoreByteReader`); past it `DeserializeCallDepthExceeded` is thrown. Mirror
/// that bound here so a deeply nested `Cand`/`Cor`/`Cthreshold` chain from peer
/// data (a box register or context-extension `SigmaProp` constant) is rejected
/// rather than overflowing the worker-thread stack.
const MAX_SIGMA_TREE_DEPTH: usize = 110;

pub(super) fn read_sigma_boolean_at_depth(
    r: &mut VlqReader,
    depth: usize,
) -> Result<SigmaBoolean, ReadError> {
    // `>=`: depth is 0-based (root enters at 0) while Scala increments the
    // shared reader level BEFORE parsing each nested node, so Rust `depth` ==
    // Scala `level - 1`; `depth >= MAX` matches Scala's `level > MaxTreeDepth`.
    if depth >= MAX_SIGMA_TREE_DEPTH {
        return Err(ReadError::DepthLimitExceeded {
            max: MAX_SIGMA_TREE_DEPTH,
        });
    }
    let tag = r.get_u8()?;
    let next = depth + 1;
    match tag {
        TRIVIAL_PROP_FALSE => Ok(SigmaBoolean::TrivialProp(false)),
        TRIVIAL_PROP_TRUE => Ok(SigmaBoolean::TrivialProp(true)),
        PROVE_DLOG => Ok(SigmaBoolean::ProveDlog(read_group_element(r)?)),
        PROVE_DHTUPLE => {
            let g = read_group_element(r)?;
            let h = read_group_element(r)?;
            let u = read_group_element(r)?;
            let v = read_group_element(r)?;
            Ok(SigmaBoolean::ProveDHTuple { g, h, u, v })
        }
        SIGMA_AND => {
            let count = r.get_u16()? as usize;
            let mut children = Vec::with_capacity(count);
            for _ in 0..count {
                children.push(read_sigma_boolean_at_depth(r, next)?);
            }
            Ok(SigmaBoolean::Cand(children))
        }
        SIGMA_OR => {
            let count = r.get_u16()? as usize;
            let mut children = Vec::with_capacity(count);
            for _ in 0..count {
                children.push(read_sigma_boolean_at_depth(r, next)?);
            }
            Ok(SigmaBoolean::Cor(children))
        }
        SIGMA_THRESHOLD => {
            // Scala: k = r.getUShort(), n = r.getUShort()
            let k = r.get_u16()?;
            let count = r.get_u16()? as usize;
            let mut children = Vec::with_capacity(count);
            for _ in 0..count {
                children.push(read_sigma_boolean_at_depth(r, next)?);
            }
            Ok(SigmaBoolean::Cthreshold { k, children })
        }
        _ => Err(ReadError::InvalidData(format!(
            "unknown SigmaBoolean tag: 0x{tag:02X}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sigma_type::SigmaType;
    use crate::sigma_value::{read_value, write_constant, write_value, SigmaValue};
    use ergo_primitives::group_element::GroupElement;

    // ----- helpers -----

    fn roundtrip_value(tpe: &SigmaType, val: &SigmaValue) {
        let mut w = VlqWriter::new();
        write_value(&mut w, tpe, val).unwrap();
        let data = w.result();
        let mut r = VlqReader::new(&data);
        let decoded = read_value(&mut r, tpe).unwrap();
        assert!(r.is_empty(), "leftover bytes for {tpe:?}");
        assert_eq!(&decoded, val);
    }

    // -- Helper: fake group element --
    fn fake_ge(prefix: u8) -> GroupElement {
        let mut bytes = [prefix; 33];
        bytes[0] = 0x02; // valid SEC1 compressed prefix
        GroupElement::from_bytes(bytes)
    }

    // ===== 2. SigmaProp roundtrips =====

    #[test]
    fn roundtrip_sigma_prop_prove_dlog() {
        let sb = SigmaBoolean::ProveDlog(fake_ge(0xBB));
        roundtrip_value(&SigmaType::SSigmaProp, &SigmaValue::SigmaProp(sb));
    }

    #[test]
    fn roundtrip_sigma_prop_prove_dh_tuple() {
        let sb = SigmaBoolean::ProveDHTuple {
            g: fake_ge(0x11),
            h: fake_ge(0x22),
            u: fake_ge(0x33),
            v: fake_ge(0x44),
        };
        roundtrip_value(&SigmaType::SSigmaProp, &SigmaValue::SigmaProp(sb));
    }

    #[test]
    fn roundtrip_sigma_prop_trivial() {
        roundtrip_value(
            &SigmaType::SSigmaProp,
            &SigmaValue::SigmaProp(SigmaBoolean::TrivialProp(true)),
        );
        roundtrip_value(
            &SigmaType::SSigmaProp,
            &SigmaValue::SigmaProp(SigmaBoolean::TrivialProp(false)),
        );
    }

    #[test]
    fn roundtrip_sigma_prop_cand() {
        let sb = SigmaBoolean::Cand(vec![
            SigmaBoolean::ProveDlog(fake_ge(0xAA)),
            SigmaBoolean::ProveDlog(fake_ge(0xBB)),
        ]);
        roundtrip_value(&SigmaType::SSigmaProp, &SigmaValue::SigmaProp(sb));
    }

    #[test]
    fn roundtrip_sigma_prop_cor() {
        let sb = SigmaBoolean::Cor(vec![
            SigmaBoolean::ProveDlog(fake_ge(0xCC)),
            SigmaBoolean::ProveDHTuple {
                g: fake_ge(0x11),
                h: fake_ge(0x22),
                u: fake_ge(0x33),
                v: fake_ge(0x44),
            },
        ]);
        roundtrip_value(&SigmaType::SSigmaProp, &SigmaValue::SigmaProp(sb));
    }

    #[test]
    fn roundtrip_sigma_prop_threshold() {
        let sb = SigmaBoolean::Cthreshold {
            k: 2,
            children: vec![
                SigmaBoolean::ProveDlog(fake_ge(0xAA)),
                SigmaBoolean::ProveDlog(fake_ge(0xBB)),
                SigmaBoolean::ProveDlog(fake_ge(0xCC)),
            ],
        };
        roundtrip_value(&SigmaType::SSigmaProp, &SigmaValue::SigmaProp(sb));
    }

    #[test]
    fn read_sigma_boolean_within_depth_limit_roundtrips() {
        // A single-child Cand chain within MaxTreeDepth (110) must still parse.
        let mut sb = SigmaBoolean::TrivialProp(true);
        for _ in 0..100 {
            sb = SigmaBoolean::Cand(vec![sb]);
        }
        roundtrip_value(&SigmaType::SSigmaProp, &SigmaValue::SigmaProp(sb));
    }

    #[test]
    fn read_sigma_boolean_deep_nesting_rejected_not_overflow() {
        // A SigmaProp constant value is peer-controllable (box register /
        // context extension). A long single-child Cand chain (~3 wire bytes per
        // level) must be REJECTED at the MaxTreeDepth bound rather than
        // recursing unbounded and overflowing the worker-thread stack — Scala
        // throws DeserializeCallDepthExceeded past depth 110.
        let mut sb = SigmaBoolean::TrivialProp(true);
        for _ in 0..200 {
            sb = SigmaBoolean::Cand(vec![sb]);
        }
        let mut w = VlqWriter::new();
        write_value(&mut w, &SigmaType::SSigmaProp, &SigmaValue::SigmaProp(sb)).unwrap();
        let data = w.result();
        let mut r = VlqReader::new(&data);
        let err = read_value(&mut r, &SigmaType::SSigmaProp).unwrap_err();
        assert!(
            matches!(err, ReadError::DepthLimitExceeded { max } if max == MAX_SIGMA_TREE_DEPTH),
            "expected depth-limit error, got {err:?}"
        );
    }

    #[test]
    fn read_sigma_boolean_depth_boundary_matches_scala() {
        // Scala rejects the 110-deep chain (level reaches 111 before the leaf)
        // and accepts the 109-deep one. With a 0-based counter and `depth >=
        // MAX`, our leaf sits at depth == (#Cand), so 110 Cands reject and 109
        // accept — the exact Scala boundary.
        let chain = |n: usize| {
            let mut sb = SigmaBoolean::TrivialProp(true);
            for _ in 0..n {
                sb = SigmaBoolean::Cand(vec![sb]);
            }
            let mut w = VlqWriter::new();
            write_value(&mut w, &SigmaType::SSigmaProp, &SigmaValue::SigmaProp(sb)).unwrap();
            w.result()
        };
        // 109 Cands: accepted.
        let ok = chain(MAX_SIGMA_TREE_DEPTH - 1);
        assert!(read_value(&mut VlqReader::new(&ok), &SigmaType::SSigmaProp).is_ok());
        // 110 Cands: rejected (matches Scala level 111 > MaxTreeDepth).
        let bad = chain(MAX_SIGMA_TREE_DEPTH);
        assert!(matches!(
            read_value(&mut VlqReader::new(&bad), &SigmaType::SSigmaProp).unwrap_err(),
            ReadError::DepthLimitExceeded { .. }
        ));
    }

    #[test]
    fn shared_depth_budget_across_expr_and_sigma_boundary() {
        // The leak: an inline SigmaProp constant nested inside a deep ErgoTree
        // expression used to restart the SigmaBoolean budget at 0. Scala shares
        // one CoreByteReader.level across expr + value + SigmaBoolean, so the
        // counts ADD. Here N SizeOf expr wrappers wrap a SigmaProp constant with
        // M Cands: neither N nor M alone exceeds MaxTreeDepth (110), but N+M does.
        let sigma_const = |m: usize| {
            let mut sb = SigmaBoolean::TrivialProp(true);
            for _ in 0..m {
                sb = SigmaBoolean::Cand(vec![sb]);
            }
            let mut w = VlqWriter::new();
            write_constant(&mut w, &SigmaType::SSigmaProp, &SigmaValue::SigmaProp(sb)).unwrap();
            w.result()
        };
        let body = |n: usize, m: usize| {
            let mut b = vec![0xB1u8; n]; // n SizeOf (One-arg) expr wrappers
            b.extend_from_slice(&sigma_const(m));
            b
        };
        // 60 expr + 60 sigma = 120 >= 110 → rejected via the shared budget
        // (was accepted before the fix, when the sigma counter reset to 0).
        let over = body(60, 60);
        assert!(matches!(
            crate::opcode::parse_body(&mut VlqReader::new(&over), 0).unwrap_err(),
            ReadError::DepthLimitExceeded { .. }
        ));
        // 40 expr + 40 sigma = 80 < 110 → accepted.
        let ok = body(40, 40);
        assert!(crate::opcode::parse_body(&mut VlqReader::new(&ok), 0).is_ok());
    }

    #[test]
    fn golden_prove_dlog_tag() {
        let mut w = VlqWriter::new();
        let sb = SigmaBoolean::ProveDlog(fake_ge(0x00));
        write_sigma_boolean(&mut w, &sb).unwrap();
        let data = w.result();
        assert_eq!(data[0], 0xCD);
        assert_eq!(data.len(), 1 + 33);
    }
}
