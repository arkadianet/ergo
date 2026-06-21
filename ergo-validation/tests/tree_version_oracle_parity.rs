//! Oracle-parity for the ErgoTree header-version gate. Scala's
//! `deserializeErgoTree` runs `VersionContext.withVersions(activatedScriptVersion,
//! treeVersion)`; `require(treeVersion <= activatedVersion)` throws an
//! `IllegalArgumentException` re-thrown as a `SerializerException` ("Tree version
//! (N) is above activated script version") — NOT a `ValidationException`, so a
//! future-version tree is HARD-rejected at deserialize even with the size bit set.
//!
//! Each `scala` label was blessed against the Scala oracle (sigma-state 6.0.2,
//! activated version 3): a v0/v3 size-delimited `sigmaProp(true)` tree PARSES;
//! v4/v5/v7 THROW. The node's box-script gate (`check_tree_version_supported`,
//! alongside `check_header_size_bit` / `check_v3_only_methods`) must agree.

use ergo_primitives::reader::VlqReader;
use ergo_ser::ergo_tree::{
    check_header_size_bit, check_tree_version_supported, check_v3_only_methods, read_ergo_tree,
};
use ergo_sigma::evaluator::validate_group_element;

/// Mirror box-creation accept/reject: parse the tree, apply the box-script gates,
/// and curve-check forwarded group elements. `true` = box accepted.
fn box_accepts(hexs: &str) -> bool {
    let bytes = hex::decode(hexs).unwrap();
    let mut r = VlqReader::new(&bytes);
    let tree = match read_ergo_tree(&mut r) {
        Ok(t) => t,
        Err(_) => return false,
    };
    if check_tree_version_supported(&tree).is_err()
        || check_header_size_bit(&tree).is_err()
        || check_v3_only_methods(&tree).is_err()
    {
        return false;
    }
    r.take_group_elements()
        .iter()
        .all(|ge| validate_group_element(*ge).is_ok())
}

#[test]
fn tree_version_oracle_parity() {
    // header nibble: 0x08=v0+size, 0x0B=v3+size, 0x0C=v4+size, 0x0D=v5+size,
    // 0x0F=v7+size; size VLQ(2)=0x02; body 08d3 = sigmaProp(true).
    let cases = [
        ("0802 08d3", "PARSED", true), // v0
        ("0b02 08d3", "PARSED", true), // v3 (activated)
        ("0c02 08d3", "THROW", false), // v4 > activated
        ("0d02 08d3", "THROW", false), // v5
        ("0f02 08d3", "THROW", false), // v7
    ];
    for (hex_spaced, scala, accepted) in cases {
        let hexs = hex_spaced.replace(' ', "");
        assert_eq!(
            box_accepts(&hexs),
            accepted,
            "{hexs}: Scala oracle = {scala} (accepted={accepted}), node disagreed"
        );
    }
}
