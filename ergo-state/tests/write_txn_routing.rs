//! Executable form of the `begin_write_qr`-only audit rule.
//!
//! Every production write transaction MUST go through
//! [`ergo_state::redb_util::begin_write_qr`] so quick-repair stays set on
//! every commit (the flag is non-monotonic — one commit that omits it forces
//! a full O(file-size) repair on the next dirty open, defeating it for every
//! preceding quick-repair commit). `redb_util.rs` already documents the audit
//! as "`grep \"db.begin_write()\"` over production code returns zero results";
//! this test makes that rule mechanical so a future raw `db.begin_write()`
//! fails CI instead of slipping past review.
//!
//! Heuristic: a file's "production" section is everything before its first
//! `#[cfg(test)]`. That matches the repo convention (unit tests live in a
//! trailing `#[cfg(test)] mod tests`), so test-only raw `begin_write()` calls
//! (e.g. the fixtures in `wallet/apply.rs`) are correctly excluded.

use std::fs;
use std::path::{Path, PathBuf};

/// The sole production call site of the raw redb `begin_write()` — the helper
/// that wraps it and sets `quick_repair = true`.
const ALLOWED: &str = "redb_util.rs";

/// The raw redb call the helper exists to replace. The trailing `(` excludes
/// `begin_write_qr(` (the helper's own name).
const RAW_CALL: &str = ".begin_write()";

fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).expect("read_dir src") {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            collect_rs_files(&path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}

/// Production slice of a source file: everything before the first
/// `#[cfg(test)]` attribute (or the whole file if it has none).
fn production_section(src: &str) -> &str {
    match src.find("#[cfg(test)]") {
        Some(idx) => &src[..idx],
        None => src,
    }
}

#[test]
fn all_production_write_txns_route_through_begin_write_qr() {
    let src_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    collect_rs_files(&src_root, &mut files);
    assert!(!files.is_empty(), "found no .rs files under {src_root:?}");

    let mut offenders = Vec::new();
    for file in &files {
        let name = file.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if name == ALLOWED {
            continue;
        }
        let src = fs::read_to_string(file).expect("read source file");
        if production_section(&src).contains(RAW_CALL) {
            offenders.push(
                file.strip_prefix(&src_root)
                    .unwrap_or(file)
                    .display()
                    .to_string(),
            );
        }
    }

    assert!(
        offenders.is_empty(),
        "raw `db.begin_write()` found in production code of: {offenders:?}\n\
         All production write transactions must go through \
         `ergo_state::redb_util::begin_write_qr` so quick-repair is set on \
         every commit (see redb_util.rs module docs).",
    );
}
