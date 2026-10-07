//! Bounded durable journal for local mining outcomes, separate from chain
//! state. Journal failures are visible diagnostics and never reject an already
//! applied block. Files hold no signed private transactions or wallet keys.

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use crate::inspection::MiningOutcome;
use serde::{Deserialize, Serialize};

const MAX_JOURNAL_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Debug, Default)]
pub(crate) struct OutcomeJournal {
    pub events: VecDeque<MiningOutcome>,
    path: Option<PathBuf>,
    pub last_error: Option<String>,
    /// Why the stored history was set aside at startup, kept for the life of
    /// the process so the history status keeps explaining the reset.
    recovery: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct FileJournal {
    version: u32,
    events: VecDeque<MiningOutcome>,
}

impl OutcomeJournal {
    /// Open the journal at `path`. A history that cannot be read never blocks
    /// startup: the file is moved aside as `<name>.corrupt-<unix ms>` and a
    /// new history starts, with the reason reported by [`Self::error`]. If it
    /// cannot even be moved, this run keeps history in memory only, so the
    /// unreadable file is never overwritten.
    pub fn open(path: &Path) -> Self {
        let problem = match read_events(path) {
            Ok(events) => {
                return Self {
                    events,
                    path: Some(path.to_owned()),
                    last_error: None,
                    recovery: None,
                }
            }
            Err(problem) => problem,
        };
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        let mut aside = path.as_os_str().to_owned();
        aside.push(format!(".corrupt-{stamp}"));
        let aside = PathBuf::from(aside);
        let (path, recovery) = match std::fs::rename(path, &aside) {
            Ok(()) => (
                Some(path.to_owned()),
                format!(
                    "{problem}; moved it to {} and started a new history",
                    aside.display()
                ),
            ),
            Err(error) => (
                None,
                format!(
                    "{problem}; it could not be moved aside ({error}), so this run's \
                     history is not saved"
                ),
            ),
        };
        Self {
            events: VecDeque::new(),
            path,
            last_error: None,
            recovery: Some(recovery),
        }
    }

    pub fn persistent(&self) -> bool {
        self.path.is_some()
    }

    /// The latest persistence failure and any startup recovery, for the
    /// history status.
    pub fn error(&self) -> Option<String> {
        match (&self.last_error, &self.recovery) {
            (Some(last), Some(recovery)) => Some(format!("{last}; {recovery}")),
            (last, recovery) => last.clone().or_else(|| recovery.clone()),
        }
    }

    pub fn append(&mut self, event: MiningOutcome) {
        // A retried accepted submission must not double-count block proceeds.
        if event.outcome == "accepted"
            && event.block_id.is_some()
            && self
                .events
                .iter()
                .any(|old| old.outcome == "accepted" && old.block_id == event.block_id)
        {
            return;
        }
        self.events.push_back(event);
        while self.events.len() > crate::handle::MAX_MINING_OUTCOMES {
            self.events.pop_front();
        }
        self.last_error = self.persist().err();
    }

    fn persist(&self) -> Result<(), String> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        let bytes = serde_json::to_vec(&FileJournal {
            version: 1,
            events: self.events.clone(),
        })
        .map_err(|e| e.to_string())?;
        if bytes.len() as u64 > MAX_JOURNAL_BYTES {
            return Err("mining history exceeds 8 MiB".into());
        }
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let temporary = parent.join(format!(
            ".mining-history-{}-{nonce}.tmp",
            std::process::id()
        ));
        let result = (|| -> std::io::Result<()> {
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(&temporary)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            std::fs::rename(&temporary, path)?;
            #[cfg(unix)]
            std::fs::File::open(parent)?.sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&temporary);
        }
        result.map_err(|e| format!("cannot persist mining history: {e}"))
    }
}

/// Stored events; a missing file is an empty history.
fn read_events(path: &Path) -> Result<VecDeque<MiningOutcome>, String> {
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(VecDeque::new()),
        Err(e) => return Err(format!("cannot open mining history: {e}")),
    };
    let mut bytes = Vec::new();
    file.take(MAX_JOURNAL_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("cannot read mining history: {e}"))?;
    if bytes.len() as u64 > MAX_JOURNAL_BYTES {
        return Err("mining history exceeds 8 MiB".into());
    }
    let parsed: FileJournal =
        serde_json::from_slice(&bytes).map_err(|e| format!("invalid mining history: {e}"))?;
    if parsed.version != 1 || parsed.events.len() > crate::handle::MAX_MINING_OUTCOMES {
        return Err("unsupported mining history version or event count".into());
    }
    Ok(parsed.events)
}

#[cfg(test)]
mod tests {
    use super::*;
    // ----- helpers -----
    fn event(block: u8, at: u64) -> MiningOutcome {
        MiningOutcome {
            msg: None,
            template_seq: None,
            block_id: Some([block; 32]),
            at_ms: at,
            outcome: "accepted".into(),
            detail: None,
            accounting: None,
        }
    }
    // ----- happy path -----
    #[test]
    fn mining_journal_persists_across_restart_and_deduplicates_applied_blocks() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("history.json");
        let mut journal = OutcomeJournal::open(&path);
        journal.append(event(1, 10));
        journal.append(event(1, 20));
        assert!(journal.last_error.is_none());
        let restored = OutcomeJournal::open(&path);
        assert_eq!(restored.events.len(), 1);
        assert_eq!(restored.events[0].at_ms, 10);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }
    // ----- error paths -----
    #[test]
    fn mining_journal_reports_persistence_failure_without_discarding_observation() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("missing").join("history.json");
        let mut journal = OutcomeJournal::open(&path);
        journal.append(event(1, 10));
        assert_eq!(journal.events.len(), 1);
        assert!(journal.last_error.is_some());
    }
    #[test]
    fn mining_journal_sets_corrupt_history_aside_and_starts_a_new_one() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("history.json");
        std::fs::write(&path, b"broken").unwrap();
        let mut journal = OutcomeJournal::open(&path);
        assert!(journal.events.is_empty());
        assert!(journal.persistent());
        let error = journal.error().unwrap();
        assert!(error.starts_with("invalid mining history"), "{error}");
        let aside: Vec<_> = std::fs::read_dir(directory.path())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|p| {
                p.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with("history.json.corrupt-")
            })
            .collect();
        assert_eq!(aside.len(), 1);
        assert!(error.contains(&aside[0].display().to_string()), "{error}");
        assert_eq!(std::fs::read(&aside[0]).unwrap(), b"broken");
        assert!(!path.exists());

        // The new history persists and keeps reporting the reset.
        journal.append(event(1, 10));
        assert!(journal.error().unwrap().contains("moved it to"));
        assert_eq!(OutcomeJournal::open(&path).events.len(), 1);
        assert_eq!(std::fs::read(&aside[0]).unwrap(), b"broken");
    }
}
