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
}

#[derive(Serialize, Deserialize)]
struct FileJournal {
    version: u32,
    events: VecDeque<MiningOutcome>,
}

impl OutcomeJournal {
    pub fn open(path: &Path) -> Result<Self, String> {
        let events = match std::fs::File::open(path) {
            Ok(file) => {
                let mut bytes = Vec::new();
                file.take(MAX_JOURNAL_BYTES + 1)
                    .read_to_end(&mut bytes)
                    .map_err(|e| format!("cannot read mining history: {e}"))?;
                if bytes.len() as u64 > MAX_JOURNAL_BYTES {
                    return Err("mining history exceeds 8 MiB".into());
                }
                let parsed: FileJournal = serde_json::from_slice(&bytes)
                    .map_err(|e| format!("invalid mining history: {e}"))?;
                if parsed.version != 1 || parsed.events.len() > crate::handle::MAX_MINING_OUTCOMES {
                    return Err("unsupported mining history version or event count".into());
                }
                parsed.events
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => VecDeque::new(),
            Err(e) => return Err(format!("cannot open mining history: {e}")),
        };
        Ok(Self {
            events,
            path: Some(path.to_owned()),
            last_error: None,
        })
    }

    pub fn persistent(&self) -> bool {
        self.path.is_some()
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
        let mut journal = OutcomeJournal::open(&path).unwrap();
        journal.append(event(1, 10));
        journal.append(event(1, 20));
        assert!(journal.last_error.is_none());
        let restored = OutcomeJournal::open(&path).unwrap();
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
        let mut journal = OutcomeJournal::open(&path).unwrap();
        journal.append(event(1, 10));
        assert_eq!(journal.events.len(), 1);
        assert!(journal.last_error.is_some());
    }
    #[test]
    fn mining_journal_rejects_corrupt_existing_history() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("history.json");
        std::fs::write(&path, b"broken").unwrap();
        assert!(OutcomeJournal::open(&path).is_err());
    }
}
