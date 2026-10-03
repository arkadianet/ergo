//! Record the source snapshot observed before compiling this diagnostic crate.
//!
//! Runtime Git state alone cannot identify a previously built executable. The
//! snapshot and executable hash are separate evidence; this is not a signed
//! build attestation or proof against edits racing the compiler.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};

fn git(root: &Path, arguments: &[&str]) -> Option<String> {
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

fn canonical(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(object) => {
            let mut entries: Vec<_> = object.iter().collect();
            entries.sort_by_key(|(key, _)| *key);
            serde_json::Value::Object(
                entries
                    .into_iter()
                    .map(|(key, value)| (key.clone(), canonical(value)))
                    .collect(),
            )
        }
        serde_json::Value::Array(values) => {
            serde_json::Value::Array(values.iter().map(canonical).collect())
        }
        other => other.clone(),
    }
}

fn walk(root: &Path, directory: &Path, files: &mut BTreeSet<PathBuf>) -> std::io::Result<()> {
    println!("cargo:rerun-if-changed={}", directory.display());
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
            walk(root, &path, files)?;
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR")?);
    let root = manifest.parent().expect("workspace crate directory");
    // A disposable copy nested under another repository must not inherit that
    // repository's revision. Only the exact workspace root owns this metadata.
    let git_root =
        git(root, &["rev-parse", "--show-toplevel"]).and_then(|path| fs::canonicalize(path).ok());
    let own_git = git_root.as_deref() == Some(fs::canonicalize(root)?.as_path());
    let mut files = BTreeSet::new();
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
                println!("cargo:rerun-if-changed={}", root.join(path).display());
            }
        }
        if let Some(reference) = git(root, &["symbolic-ref", "-q", "HEAD"]) {
            if let Some(path) = git(root, &["rev-parse", "--git-path", &reference]) {
                println!("cargo:rerun-if-changed={}", root.join(path).display());
            }
        }
        git(root, &["rev-parse", "HEAD"])
    } else {
        walk(root, root, &mut files)?;
        None
    };
    // Directory watches also notice newly added authored files in a checkout.
    for directory in fs::read_dir(root)? {
        let directory = directory?;
        if directory.file_type()?.is_dir()
            && (directory.file_name().to_string_lossy().starts_with("ergo-")
                || matches!(
                    directory.file_name().to_str(),
                    Some("scripts" | "test-vectors" | "docs" | ".github")
                ))
        {
            println!("cargo:rerun-if-changed={}", directory.path().display());
            // Authored source can be included by Rust even when a broad
            // local ignore rule omitted a newly added file from git ls-files.
            let authored = directory.path().join("src");
            if authored.is_dir() {
                walk(root, &authored, &mut files)?;
            }
        }
    }
    let mut rows = Vec::new();
    for relative in files {
        let path = root.join(&relative);
        match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                rows.push(serde_json::json!({"path": relative, "status": "MISSING"}));
                continue;
            }
            Err(error) => return Err(error.into()),
            Ok(_) => {}
        }
        // Symlink target text is source metadata, not permission to read a
        // target outside this owned source tree.
        let bytes = if path.is_symlink() {
            fs::read_link(&path)?.to_string_lossy().as_bytes().to_vec()
        } else {
            fs::read(&path)?
        };
        println!("cargo:rerun-if-changed={}", path.display());
        rows.push(serde_json::json!({
            "path": relative, "bytes": bytes.len(),
            "sha256": format!("{:x}", Sha256::digest(&bytes)),
        }));
    }
    let rows = canonical(&serde_json::to_value(rows)?);
    let source_sha256 = format!("{:x}", Sha256::digest(serde_json::to_vec(&rows)?));
    let rustc = Command::new(std::env::var("RUSTC")?).arg("-vV").output()?;
    if !rustc.status.success() {
        return Err("cannot identify build compiler".into());
    }
    let mut features: Vec<_> = std::env::vars()
        .filter_map(|(name, _)| name.strip_prefix("CARGO_FEATURE_").map(str::to_string))
        .collect();
    features.sort();
    let metadata = serde_json::json!({
        "schema": 1,
        "scope": "workspace source snapshot observed by build script; not a signed build attestation",
        "git_revision": revision,
        "git_dirty": if own_git { git(root, &["status", "--porcelain"]).map(|status| !status.is_empty()) } else { None },
        "source_sha256": source_sha256,
        "files": rows,
        "rustc": String::from_utf8(rustc.stdout)?,
        "target": std::env::var("TARGET")?,
        "profile": std::env::var("PROFILE")?,
        "encoded_rustflags": std::env::var("CARGO_ENCODED_RUSTFLAGS").ok(),
        "features": features,
    });
    fs::write(
        PathBuf::from(std::env::var("OUT_DIR")?).join("source-snapshot.json"),
        serde_json::to_vec(&metadata)?,
    )?;
    Ok(())
}
