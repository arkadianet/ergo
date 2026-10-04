//! Record the source snapshot observed before compiling this diagnostic crate.
//!
//! Runtime Git state alone cannot identify a previously built executable. The
//! snapshot and executable hash are separate evidence; this is not a signed
//! build attestation or proof against edits racing the compiler.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};

#[path = "src/source_inventory.rs"]
mod source_inventory;

use source_inventory::{compiled_rows, git, inventory, rows_sha256};

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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR")?);
    let root = manifest.parent().expect("workspace crate directory");
    let inventory = inventory(root)?;
    for path in &inventory.watched {
        println!("cargo:rerun-if-changed={}", path.display());
    }
    let mut rows = Vec::new();
    for relative in &inventory.files {
        let path = root.join(relative);
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
    let rows = canonical(&serde_json::Value::Array(rows));
    let rows = rows.as_array().expect("snapshot rows");
    let source_sha256 = rows_sha256(rows)?;
    // Comparison keys bind only what Cargo compiles. Hashing every file would
    // make each baseline edit change the key it records.
    let compiled_source_sha256 = rows_sha256(&compiled_rows(rows))?;
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
        "git_revision": inventory.revision,
        "git_dirty": if inventory.own_git { git(root, &["status", "--porcelain"]).map(|status| !status.is_empty()) } else { None },
        "source_sha256": source_sha256,
        "compiled_source_sha256": compiled_source_sha256,
        "files": rows,
        "rustc": String::from_utf8(rustc.stdout)?,
        "target": std::env::var("TARGET")?,
        "profile": std::env::var("PROFILE")?,
        "encoded_rustflags": std::env::var("CARGO_ENCODED_RUSTFLAGS").ok(),
        "features": features,
    });
    fs::write(
        Path::new(&std::env::var("OUT_DIR")?).join("source-snapshot.json"),
        serde_json::to_vec(&metadata)?,
    )?;
    Ok(())
}
