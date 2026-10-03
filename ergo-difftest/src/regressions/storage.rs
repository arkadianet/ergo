//! Complete diagnostic record publication and a derived pending queue.
//!
//! File synchronization and atomic publication prevent partial visible JSON.
//! This is diagnostic storage, not a database transaction or power-loss proof.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use super::DivergenceRecord;

pub(crate) fn canonical(value: &serde_json::Value) -> serde_json::Value {
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

pub(crate) fn digest(value: &serde_json::Value) -> io::Result<String> {
    let bytes = serde_json::to_vec(&canonical(value)).map_err(io::Error::other)?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

pub(super) fn validate_surface(surface: &str) -> io::Result<()> {
    if surface.is_empty()
        || !surface
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "surface must be a plain lowercase identifier",
        ));
    }
    Ok(())
}

fn directory(path: &Path) -> io::Result<()> {
    fs::create_dir_all(path)?;
    if fs::symlink_metadata(path)?.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "diagnostic output directory must not be a symlink",
        ));
    }
    Ok(())
}

fn lock(root: &Path) -> io::Result<File> {
    directory(root)?;
    let path = root.join(".filing.lock");
    if path.is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "filing lock must not be a symlink",
        ));
    }
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(path)?;
    lock.lock()?;
    Ok(lock)
}

/// Publish immutable complete bytes; an identical existing file is idempotent.
pub(crate) fn publish(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "output has no parent"))?;
    directory(parent)?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary.write_all(bytes)?;
    temporary.as_file().sync_all()?;
    match temporary.persist_noclobber(path) {
        Ok(_) => Ok(()),
        Err(error) if error.error.kind() == io::ErrorKind::AlreadyExists => {
            if path.is_symlink() || fs::read(path)? != bytes {
                Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "existing evidence differs or is a symlink; refusing overwrite",
                ))
            } else {
                Ok(())
            }
        }
        Err(error) => Err(error.error),
    }
}

pub(super) fn file(record: &DivergenceRecord, root: &Path) -> io::Result<PathBuf> {
    validate_surface(&record.surface)?;
    if record.triage != "PENDING"
        && !(record.triage.starts_with("KnownArtifact(") && record.triage.ends_with(')'))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "unrecognized triage disposition",
        ));
    }
    let _lock = lock(root)?;
    let value = canonical(&serde_json::to_value(record).map_err(io::Error::other)?);
    let identity = digest(&value)?;
    let parent = if record.triage == "PENDING" {
        root.join(&record.surface)
    } else {
        let artifacts = root.join("artifacts");
        directory(&artifacts)?;
        artifacts.join(&record.surface)
    };
    directory(&parent)?;
    let path = parent.join(format!("{identity}.json"));
    let mut bytes = serde_json::to_vec_pretty(&value).map_err(io::Error::other)?;
    bytes.push(b'\n');
    publish(&path, &bytes)?;
    // The lock serializes both publication and view regeneration. If updating
    // the view fails, the complete immutable record remains recoverable.
    regenerate_queue(root)?;
    Ok(path)
}

fn regenerate_queue(root: &Path) -> io::Result<()> {
    let mut entries = Vec::new();
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir()
            || entry.file_name() == "artifacts"
            || entry.file_name() == "runs"
        {
            continue;
        }
        let surface = entry.file_name().to_string_lossy().into_owned();
        validate_surface(&surface)?;
        for file in fs::read_dir(entry.path())? {
            let file = file?;
            if file
                .path()
                .extension()
                .is_none_or(|extension| extension != "json")
            {
                continue;
            }
            if !file.file_type()?.is_file() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "record is not a regular file",
                ));
            }
            let value: serde_json::Value =
                serde_json::from_slice(&fs::read(file.path())?).map_err(io::Error::other)?;
            let record: DivergenceRecord =
                serde_json::from_value(value.clone()).map_err(io::Error::other)?;
            if record.surface != surface {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "record surface/directory mismatch",
                ));
            }
            let filename = file
                .path()
                .file_stem()
                .expect("json stem")
                .to_string_lossy()
                .into_owned();
            let identity = digest(&value)?;
            if filename != identity {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "record identity mismatch; preserve legacy records and select a fresh output directory"));
            }
            if record.triage == "PENDING" {
                entries.push(format!(
                    "- [PENDING] {surface}/{identity} — {}\n",
                    record.repro
                ));
            }
        }
    }
    entries.sort();
    let mut queue = tempfile::NamedTempFile::new_in(root)?;
    queue.write_all(b"# Pending diagnostic records\n\nDerived from immutable JSON records; rebuild by filing a record.\n\n")?;
    for entry in entries {
        queue.write_all(entry.as_bytes())?;
    }
    queue.as_file().sync_all()?;
    queue
        .persist(root.join("QUEUE.md"))
        .map_err(|error| error.error)?;
    Ok(())
}
