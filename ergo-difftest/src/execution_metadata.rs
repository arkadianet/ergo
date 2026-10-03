//! Immutable execution journals for diagnostic comparisons.
//!
//! The build-script snapshot identifies observed source; the executable hash
//! identifies the running binary. Neither is a signed build attestation. An
//! unavailable JVM identity remains explicit and cannot authorize a baseline.

use std::io;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::oracle::Oracle;
use crate::regressions::{storage, DivergenceRecord};

/// Published journal and the source archives needed to reproduce a comparison.
pub struct ExecutionMetadata {
    reference: String,
    identity: String,
    contract: Value,
    primary: PathBuf,
    sidecar: Option<PathBuf>,
}

fn executable_identity(path: &Path) -> io::Result<Value> {
    let bytes = std::fs::read(path)?;
    Ok(
        json!({"path": path, "bytes": bytes.len(), "sha256": format!("{:x}", Sha256::digest(bytes))}),
    )
}

fn command_identity() -> io::Result<Value> {
    let path = std::env::var_os("PATH")
        .into_iter()
        .flat_map(|paths| std::env::split_paths(&paths).collect::<Vec<_>>())
        .map(|directory| {
            directory.join(if cfg!(windows) {
                "scala-cli.exe"
            } else {
                "scala-cli"
            })
        })
        .find(|path| path.is_file());
    match path {
        Some(path) => executable_identity(&path),
        None => Ok(
            json!({"status": "executable identity unavailable; no version inferred from directives"}),
        ),
    }
}

fn archive_source(source: &Value, root: &Path) -> io::Result<PathBuf> {
    let text = source["source_snapshot_utf8"].as_str().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "oracle source snapshot unavailable",
        )
    })?;
    let identity = format!("{:x}", Sha256::digest(text.as_bytes()));
    if source["source_sha256"].as_str() != Some(&identity) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "oracle source identity mismatch",
        ));
    }
    let relative = PathBuf::from("runs").join(format!("{identity}.scala"));
    storage::publish(&root.join(&relative), text.as_bytes())?;
    Ok(relative)
}

fn stable_oracle(source: &Value) -> Value {
    let runtime = &source["actual_runtime"];
    let properties = &runtime["properties"];
    let jars: Vec<Value> = runtime["resolved_jars"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|jar| json!({"name": jar["name"], "sha256": jar["sha256"]}))
        .collect();
    let mut result = json!({
        "source_sha256": source["source_sha256"],
        "runtime": {
            "java.runtime.version": properties["java.runtime.version"],
            "java.vm.name": properties["java.vm.name"],
            "java.vendor": properties["java.vendor"],
            "resolved_jars_in_classpath_order": jars,
        },
        "complete": properties["java.runtime.version"].is_string() && !jars.is_empty(),
    });
    if source.get("verify_sidecar").is_some() {
        result["verify_sidecar"] = stable_oracle(&source["verify_sidecar"]);
    }
    result
}

fn shell_quote(text: &str) -> String {
    format!("'{}'", text.replace('\'', "'\\''"))
}

impl ExecutionMetadata {
    /// Capture actual authority and publish one immutable journal per run.
    /// A failed runtime capture still archives sources with an explicit error.
    pub fn capture(oracle: &Oracle, root: &Path, request: Value) -> io::Result<Self> {
        let (source, error) = match oracle.provenance() {
            Ok(source) => (source, None),
            Err(error) => (oracle.source_snapshots(), Some(error.to_string())),
        };
        let primary = archive_source(&source, root)?;
        let sidecar = source
            .get("verify_sidecar")
            .map(|source| archive_source(source, root))
            .transpose()?;
        let build: Value = serde_json::from_str(include_str!(concat!(
            env!("OUT_DIR"),
            "/source-snapshot.json"
        )))
        .map_err(io::Error::other)?;
        let scala_cli = command_identity()?;
        let contract = json!({
            "schema": 1,
            "rust": {
                "source_sha256": build["source_sha256"], "rustc": build["rustc"],
                "target": build["target"], "profile": build["profile"],
                "features": build["features"], "encoded_rustflags": build["encoded_rustflags"],
            },
            "oracle": stable_oracle(&source),
            "scala_cli_sha256": scala_cli["sha256"],
        });
        let metadata = storage::canonical(&json!({
            "schema": 1, "build": build,
            "executable": executable_identity(&std::env::current_exe()?)?,
            "scala_cli_executable": scala_cli,
            "request": request,
            "oracle": source, "authority_error": error,
            "comparison_contract": contract,
            "source_archives": {"primary": primary, "verify_sidecar": sidecar},
        }));
        let identity = storage::digest(&metadata)?;
        let reference = format!("runs/{identity}.json");
        let mut bytes = serde_json::to_vec_pretty(&metadata).map_err(io::Error::other)?;
        bytes.push(b'\n');
        storage::publish(&root.join(&reference), &bytes)?;
        Ok(Self {
            reference,
            identity,
            contract,
            primary,
            sidecar,
        })
    }

    /// Whether this surface has actual executing JVM and resolved JAR evidence.
    pub fn complete_for(&self, surface: &str) -> bool {
        let oracle = &self.contract["oracle"];
        let authority = if surface == "verify" {
            &oracle["verify_sidecar"]
        } else {
            oracle
        };
        authority["complete"] == true
    }

    /// Attach source-bound comparison identity and an archived-source repro.
    pub fn attach(&self, record: &mut DivergenceRecord, root: &Path) -> io::Result<()> {
        let mut contract = self.contract.clone();
        contract["surface_policy"] = surface_policy(&record.surface).into();
        let complete = self.complete_for(&record.surface);
        let key = if complete {
            Some(baseline_key(record, &contract)?)
        } else {
            None
        };
        record.execution = Some(json!({
            "metadata": self.reference, "metadata_sha256": self.identity,
            "comparison_contract": contract, "authority_complete": complete,
            "baseline_key": key,
        }));
        let sidecar = self
            .sidecar
            .as_ref()
            .map(|path| {
                format!(
                    "DIFFTEST_VERIFY_ORACLE_SCRIPT={} ",
                    shell_quote(&root.join(path).to_string_lossy())
                )
            })
            .unwrap_or_default();
        record.repro = format!(
            "{sidecar}difftest --oracle --oracle-script {} --repro {} --surface {}",
            shell_quote(&root.join(&self.primary).to_string_lossy()),
            record.input_hex,
            record.surface
        );
        Ok(())
    }
}

/// Stable semantic key: excludes seed, iteration, temporary paths and triage.
/// Full record publication still includes all evidence in its separate digest.
pub fn baseline_key(record: &DivergenceRecord, contract: &Value) -> io::Result<String> {
    storage::digest(&json!({
        "surface": record.surface, "kind": record.kind, "input_hex": record.input_hex,
        "rust": record.rust, "jvm": record.jvm, "comparison_contract": contract,
    }))
}

fn surface_policy(surface: &str) -> &'static str {
    match surface {
        "reduce" => "activated version 3; fixed dummy reduction context defined by archived sources; no transaction verification",
        "reduce_ctx" => "activated version 3; framed extension and SELF registers; remaining dummy context defined by archived sources; no transaction verification",
        "verify" => "JSON request carries activated version and context; initial Rust decoding version 1; archived verifier sources define the full contract",
        "validate" => "statelessValidity only; no contextual transaction or block validation",
        "verify_avl" => "framed AVL operations and proof; wire/digest comparison defined by archived sources",
        "header" => "header codec comparison; no chain membership or proof-of-work acceptance",
        _ => "wire codec comparison; Rust activated reader version 3; accepted input is restricted to the consumed object range",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- happy path -----

    #[test]
    fn stable_authority_ignores_paths_but_binds_sources_jars_and_versions() {
        let first = json!({"source_sha256": "source", "actual_runtime": {
            "properties": {"java.runtime.version": "17", "java.vendor": "vendor", "java.home": "/a"},
            "resolved_jars": [{"name": "reference.jar", "sha256": "hash", "path": "/a.jar"}]
        }});
        let mut moved = first.clone();
        moved["actual_runtime"]["properties"]["java.home"] = "/b".into();
        moved["actual_runtime"]["resolved_jars"][0]["path"] = "/b.jar".into();
        assert_eq!(stable_oracle(&first), stable_oracle(&moved));
        moved["actual_runtime"]["resolved_jars"][0]["sha256"] = "changed".into();
        assert_ne!(stable_oracle(&first), stable_oracle(&moved));
        moved = first.clone();
        moved["source_sha256"] = "changed".into();
        assert_ne!(stable_oracle(&first), stable_oracle(&moved));
    }

    // ----- error paths -----

    #[test]
    fn unqueried_oracle_cannot_bind_a_baseline() {
        assert_eq!(
            stable_oracle(&json!({"source_sha256": "source"}))["complete"],
            false
        );
    }

    #[test]
    fn source_archive_changed_original_is_preserved_and_conflict_is_refused() {
        let root = tempfile::tempdir().unwrap();
        let source = "// ordinary diagnostic source fixture\n";
        let metadata = json!({
            "source_snapshot_utf8": source,
            "source_sha256": format!("{:x}", Sha256::digest(source.as_bytes())),
        });
        let relative = archive_source(&metadata, root.path()).unwrap();
        assert_eq!(
            std::fs::read_to_string(root.path().join(&relative)).unwrap(),
            source
        );
        std::fs::write(root.path().join(relative), "changed").unwrap();
        assert_eq!(
            archive_source(&metadata, root.path()).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
    }
}
