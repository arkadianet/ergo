//! Workspace source inventory for the build-script snapshot.
//!
//! `build.rs` includes this file; the crate compiles it only for its unit
//! tests. Every authored file is recorded as diagnostic evidence, but only
//! Cargo compilation inputs identify the compared Rust code, so the known-bug
//! baseline, records, docs, scripts, test vectors and fuzz corpora never change
//! a comparison key. Only compiled `src/` trees are watched as directories:
//! build and fuzz output written elsewhere cannot force a rebuild.

use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};

/// Authored files of one workspace snapshot.
pub struct Inventory {
    /// Files relative to the workspace root, including untracked authored
    /// files that Git does not ignore.
    pub files: BTreeSet<PathBuf>,
    /// Git metadata and compiled directories whose change reruns the build
    /// script; each inventoried file is watched separately.
    pub watched: Vec<PathBuf>,
    /// Whether the workspace root owns its Git repository.
    pub own_git: bool,
    /// Checked-out revision when the workspace root owns its Git repository.
    pub revision: Option<String>,
}

pub fn git(root: &Path, arguments: &[&str]) -> Option<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(arguments)
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Whether `path`, relative to the workspace root, is a Cargo input of the
/// workspace build: the root manifest, lockfile or toolchain pin, or a crate's
/// manifest, build script or `src/` tree.
pub fn is_compiled_input(path: &Path) -> bool {
    let mut parts = path.components().map(|part| match part {
        Component::Normal(name) => name.to_str(),
        _ => None,
    });
    let crate_dir = |name: Option<&str>| name.is_some_and(|name| name.starts_with("ergo-"));
    match (parts.next(), parts.next(), parts.next()) {
        (Some(Some("Cargo.toml" | "Cargo.lock" | "rust-toolchain.toml")), None, None) => true,
        (Some(name), Some(Some("Cargo.toml" | "build.rs")), None) => crate_dir(name),
        (Some(name), Some(Some("src")), _) => crate_dir(name),
        _ => false,
    }
}

/// Snapshot rows of compiled inputs, in snapshot order.
pub fn compiled_rows(rows: &[serde_json::Value]) -> Vec<serde_json::Value> {
    rows.iter()
        .filter(|row| {
            row["path"]
                .as_str()
                .is_some_and(|path| is_compiled_input(Path::new(path)))
        })
        .cloned()
        .collect()
}

/// SHA-256 of canonical snapshot rows, as `scripts/difftest-records.py`
/// digests them.
pub fn rows_sha256(rows: &[serde_json::Value]) -> Result<String, serde_json::Error> {
    Ok(format!("{:x}", Sha256::digest(serde_json::to_vec(rows)?)))
}

fn walk(
    root: &Path,
    directory: &Path,
    files: &mut BTreeSet<PathBuf>,
    watched: &mut Vec<PathBuf>,
) -> io::Result<()> {
    // A compiled directory is watched so a new module reruns the snapshot.
    // Any other directory may receive build, fuzz or record output.
    if is_compiled_input(directory.strip_prefix(root).unwrap_or(directory)) {
        watched.push(directory.to_path_buf());
    }
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let path = entry.path();
        if entry.file_type()?.is_dir() {
            let name = entry.file_name();
            if matches!(
                name.to_str(),
                Some(
                    ".git"
                        | "target"
                        | "audit"
                        | ".superpowers"
                        | ".scala-build"
                        | ".bsp"
                        | "node_modules"
                        | "artifacts"
                )
            ) {
                continue;
            }
            walk(root, &path, files, watched)?;
        } else if entry.file_type()?.is_file() {
            files.insert(
                path.strip_prefix(root)
                    .expect("workspace descendant")
                    .to_path_buf(),
            );
        }
    }
    Ok(())
}

/// Inventory the workspace rooted at `root`.
pub fn inventory(root: &Path) -> Result<Inventory, Box<dyn std::error::Error>> {
    // A disposable copy nested under another repository must not inherit that
    // repository's revision. Only the exact workspace root owns this metadata.
    let git_root =
        git(root, &["rev-parse", "--show-toplevel"]).and_then(|path| fs::canonicalize(path).ok());
    let own_git = git_root.as_deref() == Some(fs::canonicalize(root)?.as_path());
    let mut files = BTreeSet::new();
    let mut watched = Vec::new();
    let revision = if own_git {
        let output = Command::new("git")
            .arg("-C")
            .arg(root)
            .args([
                "ls-files",
                "--cached",
                "--others",
                "--exclude-standard",
                "-z",
            ])
            .output()?;
        if !output.status.success() {
            return Err("cannot enumerate source snapshot".into());
        }
        for path in output
            .stdout
            .split(|byte| *byte == 0)
            .filter(|path| !path.is_empty())
        {
            files.insert(PathBuf::from(std::str::from_utf8(path)?));
        }
        for name in ["HEAD", "packed-refs"] {
            if let Some(path) = git(root, &["rev-parse", "--git-path", name]) {
                watched.push(root.join(path));
            }
        }
        if let Some(reference) = git(root, &["symbolic-ref", "-q", "HEAD"]) {
            if let Some(path) = git(root, &["rev-parse", "--git-path", &reference]) {
                watched.push(root.join(path));
            }
        }
        git(root, &["rev-parse", "HEAD"])
    } else {
        walk(root, root, &mut files, &mut watched)?;
        None
    };
    // Authored source can be included by Rust even when a broad local ignore
    // rule omitted a newly added file from git ls-files.
    for directory in fs::read_dir(root)? {
        let directory = directory?;
        if directory.file_type()?.is_dir()
            && directory.file_name().to_string_lossy().starts_with("ergo-")
        {
            let authored = directory.path().join("src");
            if authored.is_dir() {
                walk(root, &authored, &mut files, &mut watched)?;
            }
        }
    }
    Ok(Inventory {
        files,
        watched,
        own_git,
        revision,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn workspace_root() -> &'static Path {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("workspace crate directory")
    }

    // ----- happy path -----

    #[test]
    fn compiled_inputs_follow_the_shared_case_table() {
        // `scripts/test_difftest_records.py` checks its copy of the rule
        // against the same table.
        let cases: Vec<(String, bool)> =
            serde_json::from_str(include_str!("../tests/compiled-inputs.json")).unwrap();
        assert!(cases.iter().any(|(_, compiled)| *compiled));
        assert!(cases.iter().any(|(_, compiled)| !*compiled));
        for (path, compiled) in cases {
            assert_eq!(is_compiled_input(Path::new(&path)), compiled, "{path}");
        }
    }

    #[test]
    fn build_snapshot_key_identity_covers_only_compiled_inputs() {
        let snapshot: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("OUT_DIR"),
            "/source-snapshot.json"
        )))
        .unwrap();
        let rows = snapshot["files"].as_array().unwrap();
        assert_eq!(snapshot["source_sha256"], rows_sha256(rows).unwrap());
        let compiled = compiled_rows(rows);
        assert!(!compiled.is_empty() && compiled.len() < rows.len());
        assert_eq!(
            snapshot["compiled_source_sha256"],
            rows_sha256(&compiled).unwrap()
        );
        // Muting a divergence edits the baseline. That edit must not change
        // the key it records, while an edit to compiled source must.
        let edited = |path: &str| {
            let mut rows = rows.clone();
            let row = rows
                .iter_mut()
                .find(|row| row["path"] == path)
                .unwrap_or_else(|| panic!("{path} is in the snapshot"));
            row["sha256"] = "0".repeat(64).into();
            rows_sha256(&compiled_rows(&rows)).unwrap()
        };
        let key = &snapshot["compiled_source_sha256"];
        assert_eq!(*key, edited("ergo-difftest/known_bugs/baseline.toml"));
        assert_ne!(*key, edited("ergo-difftest/src/lib.rs"));
    }

    #[test]
    fn inventory_watches_only_compiled_directories() {
        let root = workspace_root();
        let inventory = inventory(root).unwrap();
        assert!(inventory
            .files
            .contains(Path::new("ergo-difftest/src/source_inventory.rs")));
        let directories: Vec<_> = inventory
            .watched
            .iter()
            .filter(|path| path.is_dir())
            .collect();
        assert!(directories.contains(&&root.join("ergo-difftest/src")));
        for directory in directories {
            let relative = directory.strip_prefix(root).unwrap();
            assert!(
                is_compiled_input(relative),
                "{relative:?} can receive build, fuzz or record output"
            );
        }
        if inventory.own_git {
            assert!(inventory.revision.is_some());
            assert!(inventory.watched.iter().any(|path| path.ends_with("HEAD")));
        }
    }
}
