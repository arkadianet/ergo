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
//! Scope: every crate whose production code writes the chain-state redb.
//! Besides `ergo-state` itself, `ergo-node` commits wallet and scan tables to
//! the same database (`store.db_arc()`).
//!
//! Heuristic: comments and literal contents are blanked first. Test code is
//! then the item each `#[cfg(test)]` annotates (up to its `;` or the end of
//! its first `{ }` block), everything after an inner `#![cfg(test)]`, and
//! every module file its parent declares under `#[cfg(test)]` (an extracted
//! `tests.rs`), including files in such a module's directory (submodules and
//! `include!`d fixtures). Production code interleaves `#[cfg(test)]` helpers,
//! so no file is cut at its first test item.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Workspace crates whose production code writes the chain-state redb.
const CRATES: &[&str] = &["ergo-state", "ergo-node"];

/// Production calls named `begin_write()` that do not open a raw redb write
/// transaction, as `(crate, file under src/, receiver)`.
const ALLOWED: &[(&str, &str, &str)] = &[
    // The helper itself: it wraps the raw call and sets quick-repair.
    ("ergo-state", "redb_util.rs", "db"),
    // `WalletStore::begin_write`; `RedbWalletStore` opens its transaction
    // through `begin_write_qr` (`ergo-state/src/wallet/store.rs`).
    ("ergo-node", "node/boot/api_wiring.rs", "store"),
    ("ergo-node", "node/wallet_bridge/commands/admin.rs", "store"),
];

/// The raw redb call the helper exists to replace. The trailing `(` excludes
/// `begin_write_qr(` (the helper's own name).
const RAW_CALL: &str = ".begin_write()";

const CFG_TEST: &str = "#[cfg(test)]";
const INNER_CFG_TEST: &str = "#![cfg(test)]";

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

fn is_ident(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

/// Replace `code[from..to]` with spaces, keeping line breaks so reported
/// line numbers stay true. Ranges start and end at ASCII delimiters.
fn blank(code: &mut [u8], from: usize, to: usize) {
    let to = to.min(code.len());
    for byte in &mut code[from.min(to)..to] {
        if *byte != b'\n' {
            *byte = b' ';
        }
    }
}

fn find(code: &[u8], needle: &[u8]) -> Option<usize> {
    code.windows(needle.len())
        .position(|window| window == needle)
}

/// `src` with comments and string/char literal contents blanked, so neither
/// can fake a call or unbalance brackets.
fn blank_comments_and_literals(src: &str) -> String {
    let bytes = src.as_bytes();
    let mut out = bytes.to_vec();
    let mut i = 0;
    while i < bytes.len() {
        let rest = &bytes[i..];
        if rest.starts_with(b"//") {
            let end = find(rest, b"\n").map_or(bytes.len(), |n| i + n);
            blank(&mut out, i, end);
            i = end;
        } else if rest.starts_with(b"/*") {
            let (mut depth, mut j) = (1, i + 2);
            while j < bytes.len() && depth > 0 {
                if bytes[j..].starts_with(b"/*") {
                    depth += 1;
                    j += 2;
                } else if bytes[j..].starts_with(b"*/") {
                    depth -= 1;
                    j += 2;
                } else {
                    j += 1;
                }
            }
            blank(&mut out, i, j);
            i = j;
        } else if rest[0] == b'r' && (i == 0 || !is_ident(bytes[i - 1]) || bytes[i - 1] == b'b') {
            // Raw string `r"…"` / `r#"…"#`; anything else is an identifier.
            let hashes = rest[1..].iter().take_while(|&&byte| byte == b'#').count();
            if rest.get(1 + hashes) == Some(&b'"') {
                let open = i + 2 + hashes;
                let mut close = vec![b'"'];
                close.resize(1 + hashes, b'#');
                let end = find(&bytes[open..], &close).map_or(bytes.len(), |n| open + n);
                blank(&mut out, open, end);
                i = end + close.len();
            } else {
                i += 1;
            }
        } else if rest[0] == b'"' {
            let mut j = i + 1;
            while j < bytes.len() && bytes[j] != b'"' {
                j += if bytes[j] == b'\\' { 2 } else { 1 };
            }
            blank(&mut out, i + 1, j);
            i = j + 1;
        } else if rest[0] == b'\'' {
            // Char literal (`'x'`, `'\n'`, `'\u{..}'`), otherwise a lifetime.
            let char_len = src[i + 1..].chars().next().map_or(0, char::len_utf8);
            if rest.get(1) == Some(&b'\\') {
                let end = rest
                    .get(3..)
                    .and_then(|tail| find(tail, b"'"))
                    .map_or(bytes.len(), |n| i + 3 + n);
                blank(&mut out, i + 1, end);
                i = end + 1;
            } else if char_len > 0 && rest.get(1 + char_len) == Some(&b'\'') {
                blank(&mut out, i + 1, i + 1 + char_len);
                i += 2 + char_len;
            } else {
                i += 1;
            }
        } else {
            i += 1;
        }
    }
    String::from_utf8(out).expect("blanking whole tokens keeps UTF-8")
}

/// Length of the item that starts `code`: through its first `;` outside
/// brackets or the end of its first top-level `{ }` block. Stops before a
/// `}` that closes the enclosing block.
fn item_len(code: &[u8]) -> usize {
    let mut depth = 0i32;
    for (i, &byte) in code.iter().enumerate() {
        match byte {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => {
                depth -= 1;
                if depth < 0 {
                    return i;
                }
                if byte == b'}' && depth == 0 {
                    return i + 1;
                }
            }
            b';' if depth == 0 => return i + 1,
            _ => {}
        }
    }
    code.len()
}

/// Production code of one file: the blanked source with every
/// `#[cfg(test)]` item blanked and everything after an inner
/// `#![cfg(test)]` dropped.
fn production_code(src: &str) -> String {
    let mut code = blank_comments_and_literals(src).into_bytes();
    if let Some(at) = find(&code, INNER_CFG_TEST.as_bytes()) {
        code.truncate(at);
    }
    let mut from = 0;
    while let Some(at) = find(&code[from..], CFG_TEST.as_bytes()).map(|n| from + n) {
        let item = at + CFG_TEST.len();
        let end = item + item_len(&code[item..]);
        blank(&mut code, at, end);
        from = end;
    }
    String::from_utf8(code).expect("blanking whole tokens keeps UTF-8")
}

/// Whether `code` declares out-of-line module `name` (`mod name;`).
fn declares_module(code: &str, name: &str) -> bool {
    code.match_indices("mod").any(|(at, _)| {
        let before = at.checked_sub(1).map(|i| code.as_bytes()[i]);
        let after = &code[at + 3..];
        if before.is_some_and(is_ident) || !after.starts_with(char::is_whitespace) {
            return false;
        }
        after
            .trim_start()
            .strip_prefix(name)
            .is_some_and(|tail| tail.trim_start().starts_with(';'))
    })
}

/// Module name of `file` and the files that may declare it.
fn declaring_files(src_root: &Path, file: &Path) -> (String, Vec<PathBuf>) {
    let stem = file.file_stem().and_then(|s| s.to_str()).unwrap_or("");
    let dir = file.parent().expect("source file has a parent");
    let (name, dir) = if stem == "mod" {
        let name = dir.file_name().and_then(|s| s.to_str()).unwrap_or("");
        (name, dir.parent().expect("module directory has a parent"))
    } else {
        (stem, dir)
    };
    let parents = if dir == src_root {
        if matches!(name, "lib" | "main") {
            Vec::new()
        } else {
            vec![src_root.join("lib.rs"), src_root.join("main.rs")]
        }
    } else {
        vec![dir.with_extension("rs"), dir.join("mod.rs")]
    };
    (name.to_string(), parents)
}

/// Whether `file` only compiles for tests: a test-only module declares it
/// (or owns its directory), or its parent declares it under `#[cfg(test)]`.
fn test_only_file(src_root: &Path, file: &Path, memo: &mut HashMap<PathBuf, bool>) -> bool {
    if let Some(&known) = memo.get(file) {
        return known;
    }
    memo.insert(file.to_path_buf(), false);
    let (name, parents) = declaring_files(src_root, file);
    let mut test_only = false;
    for parent in parents.iter().filter(|parent| parent.is_file()) {
        if test_only_file(src_root, parent, memo) {
            test_only = true;
            break;
        }
        let src = fs::read_to_string(parent).expect("read parent module");
        if declares_module(&blank_comments_and_literals(&src), &name)
            && !declares_module(&production_code(&src), &name)
        {
            test_only = true;
            break;
        }
    }
    memo.insert(file.to_path_buf(), test_only);
    test_only
}

/// The identifier right before `.begin_write()`, across line breaks
/// (`db\n    .begin_write()`). Empty for a call or index receiver.
fn receiver(code: &str, call_at: usize) -> &str {
    let before = code[..call_at].trim_end();
    let start = before
        .bytes()
        .rposition(|byte| !is_ident(byte))
        .map_or(0, |i| i + 1);
    &before[start..]
}

/// `crate/file:line (receiver)` for every production raw call in `crate_name`.
fn raw_calls(workspace: &Path, crate_name: &str) -> Vec<String> {
    let src_root = workspace.join(crate_name).join("src");
    let mut files = Vec::new();
    collect_rs_files(&src_root, &mut files);
    assert!(!files.is_empty(), "found no .rs files under {src_root:?}");
    files.sort();

    let mut memo = HashMap::new();
    let mut calls = Vec::new();
    for file in &files {
        if test_only_file(&src_root, file, &mut memo) {
            continue;
        }
        let relative = file
            .strip_prefix(&src_root)
            .expect("file under src")
            .components()
            .map(|part| part.as_os_str().to_string_lossy())
            .collect::<Vec<_>>()
            .join("/");
        let code = production_code(&fs::read_to_string(file).expect("read source file"));
        for (at, _) in code.match_indices(RAW_CALL) {
            let receiver = receiver(&code, at);
            if !ALLOWED.contains(&(crate_name, relative.as_str(), receiver)) {
                let line = code[..at].matches('\n').count() + 1;
                calls.push(format!("{crate_name}/src/{relative}:{line} ({receiver})"));
            }
        }
    }
    calls
}

#[test]
fn all_production_write_txns_route_through_begin_write_qr() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("ergo-state sits in the workspace root");
    let offenders: Vec<String> = CRATES
        .iter()
        .flat_map(|crate_name| raw_calls(workspace, crate_name))
        .collect();

    assert!(
        offenders.is_empty(),
        "raw `db.begin_write()` found in production code at: {offenders:?}\n\
         All production write transactions must go through \
         `ergo_state::redb_util::begin_write_qr` so quick-repair is set on \
         every commit (see redb_util.rs module docs).",
    );
}

#[test]
fn routing_audit_skips_only_test_items() {
    let src = "\
        // db.begin_write() in a comment\n\
        #[cfg(test)]\n\
        fn helper(db: &Db) { let _ = \"}\"; db.begin_write(); }\n\
        #[cfg(test)]\n\
        mod tests;\n\
        fn production(db: &Db) {\n\
            #[cfg(test)]\n\
            if fault() { return; }\n\
            let c = '}';\n\
            ctx\n\
                .db\n\
                .begin_write();\n\
        }\n";
    let code = production_code(src);
    let calls: Vec<_> = code.match_indices(RAW_CALL).collect();
    assert_eq!(calls.len(), 1, "{code}");
    assert_eq!(receiver(&code, calls[0].0), "db");
    assert!(!declares_module(&code, "tests"));
    assert!(declares_module(&blank_comments_and_literals(src), "tests"));
}
