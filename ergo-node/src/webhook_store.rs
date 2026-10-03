//! Private durable webhook snapshot store. Signing secrets are stored in the
//! operator data directory; restrict this database to the operator account.
use ergo_api::v1::webhooks::engine::WebhookStore;
use redb::ReadableDatabase;
use std::fs::{self, OpenOptions};
use std::path::Path;

// One bounded snapshot table does not need another 1 GiB page cache. This
// limits redb's clean-page cache, not JSON snapshot allocations or process RSS.
const CACHE_BYTES: usize = 16 * 1024 * 1024;

const SNAPSHOT: redb::TableDefinition<&str, &[u8]> =
    redb::TableDefinition::new("webhook_snapshot_v1");

pub(crate) struct RedbWebhookStore {
    db: redb::Database,
}

impl RedbWebhookStore {
    pub(crate) fn open(path: &Path) -> Result<Self, String> {
        let existing = match fs::symlink_metadata(path) {
            Ok(metadata) if metadata.file_type().is_file() && metadata.len() > 0 => Some(metadata),
            Ok(_) => {
                return Err(
                    "webhook database must be a nonempty regular file, not a symlink".into(),
                )
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error.to_string()),
        };
        let created = existing.is_none();
        let mut options = OpenOptions::new();
        options.read(true).write(true).create_new(created);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(path).map_err(|e| e.to_string())?;
        let opened = file.metadata().map_err(|e| e.to_string())?;
        if !opened.is_file() {
            return Err("webhook database must be a regular file".into());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if existing.as_ref().is_some_and(|metadata| {
                metadata.dev() != opened.dev() || metadata.ino() != opened.ino()
            }) {
                return Err("webhook database changed identity while opening".into());
            }
        }
        // Keep the verified handle: dropping it and reopening the path would
        // allow a different file to receive signing secrets. Tighten existing
        // permissions only after redb validates and locks this same database.
        let permissions_file = file.try_clone().map_err(|e| e.to_string())?;
        let db = redb::Database::builder()
            .set_cache_size(CACHE_BYTES)
            .create_file(file)
            .map_err(|e| e.to_string())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            permissions_file
                .set_permissions(fs::Permissions::from_mode(0o600))
                .map_err(|e| e.to_string())?;
        }
        permissions_file.sync_all().map_err(|e| e.to_string())?;
        // A durable registration also needs the newly-created directory
        // entry to survive a crash. Windows has no portable directory sync.
        #[cfg(unix)]
        if created {
            let parent = path
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new("."));
            fs::File::open(parent)
                .and_then(|directory| directory.sync_all())
                .map_err(|e| e.to_string())?;
        }
        Ok(Self { db })
    }
}

impl WebhookStore for RedbWebhookStore {
    fn load(&self) -> Result<Option<Vec<u8>>, String> {
        let read = self.db.begin_read().map_err(|e| e.to_string())?;
        let table = match read.open_table(SNAPSHOT) {
            Ok(table) => table,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(error) => return Err(error.to_string()),
        };
        let snapshot = table.get("state").map_err(|e| e.to_string())?;
        Ok(snapshot.map(|value| value.value().to_vec()))
    }
    fn commit(&self, snapshot: &[u8]) -> Result<(), String> {
        let mut write = ergo_state::begin_write_qr(&self.db).map_err(|e| e.to_string())?;
        write
            .set_durability(redb::Durability::Immediate)
            .map_err(|e| e.to_string())?;
        {
            let mut table = write.open_table(SNAPSHOT).map_err(|e| e.to_string())?;
            table.insert("state", snapshot).map_err(|e| e.to_string())?;
        }
        write.commit().map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_api::v1::realtime::RealtimeEvent;
    use ergo_api::v1::webhooks::DeliveryOutcome;
    use ergo_api::v1::WebhookEngine;
    use std::sync::Arc;

    // ----- helpers -----

    fn event(seq: u64) -> RealtimeEvent {
        RealtimeEvent {
            seq,
            emitted_at_unix_ms: 1,
            routes: vec!["blocks".into()],
            event: "block_applied",
            confirmed: true,
            height: Some(100),
            data: serde_json::json!({"height":100}),
            previous_seq: None,
        }
    }

    // ----- happy path -----

    #[test]
    fn webhook_database_reopen_retains_retry_signature_and_acknowledgement() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("webhooks.redb");
        let store = Arc::new(RedbWebhookStore::open(&path).unwrap());
        let engine = WebhookEngine::durable(Default::default(), store.clone()).unwrap();
        let subscription = engine
            .register(
                "https://example.com/hook".into(),
                vec!["blocks".into()],
                Some("test-secret".into()),
                1,
                0,
            )
            .unwrap();
        engine.enqueue_matches(&event(17), 0);
        let first = engine.take_due(0).remove(0);
        engine.record_result(&first.delivery_id, DeliveryOutcome::HttpError(503), 10);
        let delivery = engine
            .deliveries_for(&subscription.webhook_id, 0, 1)
            .remove(0);
        let due_at = delivery.next_retry_at_unix_ms.unwrap();
        drop(engine);
        drop(store);
        let store = Arc::new(RedbWebhookStore::open(&path).unwrap());
        let engine = WebhookEngine::durable(Default::default(), store.clone()).unwrap();
        assert_eq!(
            engine
                .get(&subscription.webhook_id)
                .unwrap()
                .secret
                .as_deref(),
            Some("test-secret")
        );
        assert!(engine.take_due(due_at - 1).is_empty());
        let retried = engine.take_due(due_at).remove(0);
        assert_eq!(retried.delivery_id, first.delivery_id);
        assert_eq!(retried.body, first.body);
        let signature = retried
            .headers
            .iter()
            .find(|(key, _)| *key == "X-Ergo-Signature")
            .unwrap();
        assert_eq!(
            signature.1,
            ergo_api::v1::webhooks::sign_body("test-secret", due_at, &first.body)
        );
        engine.record_result(&retried.delivery_id, DeliveryOutcome::Success(204), due_at);
        drop(engine);
        drop(store);
        let engine = WebhookEngine::durable(
            Default::default(),
            Arc::new(RedbWebhookStore::open(&path).unwrap()),
        )
        .unwrap();
        assert!(engine.take_due(u64::MAX).is_empty());
        assert_eq!(engine.highest_event_seq(), 17);
        assert_eq!(engine.enqueue_matches(&event(17), due_at), 0);
        assert_eq!(
            engine
                .register(
                    "https://example.com/second".into(),
                    vec!["blocks".into()],
                    None,
                    0,
                    due_at
                )
                .unwrap()
                .webhook_id,
            "wh_0000000000000002"
        );
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

    #[tokio::test]
    async fn graceful_worker_shutdown_joins_hanging_attempt_before_immediate_reopen() {
        use ergo_api::v1::webhooks::worker::{spawn_webhook_worker_with_shutdown, WebhookSink};
        use ergo_api::v1::webhooks::PreparedRequest;
        use std::time::Duration;
        struct HangingSink(Arc<tokio::sync::Notify>);
        #[async_trait::async_trait]
        impl WebhookSink for HangingSink {
            async fn post(&self, _: &PreparedRequest) -> DeliveryOutcome {
                self.0.notify_one();
                std::future::pending().await
            }
        }
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("webhooks.redb");
        let store = Arc::new(RedbWebhookStore::open(&path).unwrap());
        let engine = Arc::new(WebhookEngine::durable(Default::default(), store.clone()).unwrap());
        let subscription = engine
            .register(
                "https://receiver.invalid/hook".into(),
                vec!["blocks".into()],
                Some("private".into()),
                1,
                0,
            )
            .unwrap();
        let bus = Arc::new(ergo_api::v1::realtime::RealtimeBus::blocks_only());
        let entered = Arc::new(tokio::sync::Notify::new());
        let (shutdown, signal) = tokio::sync::oneshot::channel();
        let worker = spawn_webhook_worker_with_shutdown(
            bus.clone(),
            engine.clone(),
            Arc::new(HangingSink(entered.clone())),
            Duration::from_millis(1),
            signal,
        );
        tokio::time::timeout(Duration::from_secs(10), async {
            while bus.subscriber_count() == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("worker must seed its filter and subscribe before publishing");
        bus.publish(ergo_api::v1::realtime::RealtimeEventBody::block_applied(
            1,
            "block".into(),
            100,
            1,
            1,
        ));
        tokio::time::timeout(Duration::from_secs(10), entered.notified())
            .await
            .unwrap();
        let pending = engine
            .deliveries_for(&subscription.webhook_id, 0, 1)
            .remove(0);
        assert_eq!(pending.attempts, 1);
        drop(engine);
        drop(store);
        shutdown.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(10), worker)
            .await
            .expect("shutdown must cancel and join hanging transport")
            .unwrap();
        // No sleeps or retry loop: the awaited shutdown must have released
        // every engine/database reference before a same-path restart.
        let recovered = WebhookEngine::durable(
            Default::default(),
            Arc::new(RedbWebhookStore::open(&path).unwrap()),
        )
        .unwrap();
        let request = recovered.take_due(u64::MAX).remove(0);
        assert_eq!(request.delivery_id, pending.delivery_id);
        assert_eq!(request.body, pending.body);
    }

    #[test]
    fn webhook_database_corrupt_snapshot_refuses_startup() {
        let directory = tempfile::tempdir().unwrap();
        let store =
            Arc::new(RedbWebhookStore::open(&directory.path().join("webhooks.redb")).unwrap());
        store.commit(b"not a snapshot").unwrap();
        assert!(WebhookEngine::durable(Default::default(), store).is_err());
    }

    #[test]
    fn existing_empty_and_malformed_files_are_preserved_without_reset() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("webhooks.redb");
        for bytes in [b"".as_slice(), b"not a redb database".as_slice()] {
            fs::write(&path, bytes).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
            }
            assert!(RedbWebhookStore::open(&path).is_err());
            assert!(fs::read(&path).unwrap() == bytes);
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                assert_eq!(
                    fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                    0o640
                );
            }
        }
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
        assert!(RedbWebhookStore::open(directory.path()).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_never_modify_or_chmod_their_target() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("target");
        let path = directory.path().join("webhooks.redb");
        fs::write(&target, b"untouched file").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o640)).unwrap();
        symlink(&target, &path).unwrap();
        assert!(RedbWebhookStore::open(&path).is_err());
        assert_eq!(fs::read(&target).unwrap(), b"untouched file");
        assert_eq!(
            fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o640
        );
        fs::remove_file(&path).unwrap();
        symlink("missing", &path).unwrap();
        assert!(RedbWebhookStore::open(&path).is_err());
        assert!(!directory.path().join("missing").exists());
    }

    #[cfg(unix)]
    #[test]
    fn valid_existing_store_permissions_are_tightened_before_reading_secrets() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("webhooks.redb");
        {
            let store = RedbWebhookStore::open(&path).unwrap();
            store.commit(b"private snapshot").unwrap();
        }
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let store = RedbWebhookStore::open(&path).unwrap();
        assert_eq!(store.load().unwrap().unwrap(), b"private snapshot");
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn live_writer_rejects_second_open_without_replacing_acknowledged_snapshot() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("webhooks.redb");
        let store = RedbWebhookStore::open(&path).unwrap();
        store.commit(b"acknowledged snapshot").unwrap();
        assert!(RedbWebhookStore::open(&path).is_err());
        assert_eq!(store.load().unwrap().unwrap(), b"acknowledged snapshot");
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
    }

    #[test]
    fn incompatible_snapshot_table_refuses_startup_without_resetting_rows() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("webhooks.redb");
        let incompatible = redb::TableDefinition::<&str, u64>::new("webhook_snapshot_v1");
        {
            let db = redb::Database::create(&path).unwrap();
            let txn = ergo_state::begin_write_qr(&db).unwrap();
            txn.open_table(incompatible)
                .unwrap()
                .insert("state", 47)
                .unwrap();
            txn.commit().unwrap();
        }
        let store = Arc::new(RedbWebhookStore::open(&path).unwrap());
        assert!(store.load().is_err());
        assert!(WebhookEngine::durable(Default::default(), store.clone()).is_err());
        drop(store);
        let db = redb::Database::open(&path).unwrap();
        assert_eq!(
            db.begin_read()
                .unwrap()
                .open_table(incompatible)
                .unwrap()
                .get("state")
                .unwrap()
                .unwrap()
                .value(),
            47
        );
    }

    #[test]
    fn future_file_format_is_preserved_without_creating_fresh_state() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("webhooks.redb");
        drop(RedbWebhookStore::open(&path).unwrap());
        let mut bytes = fs::read(&path).unwrap();
        bytes[64] = 4;
        bytes[192] = 4;
        fs::write(&path, &bytes).unwrap();
        assert!(RedbWebhookStore::open(&path).is_err());
        assert!(fs::read(&path).unwrap() == bytes);
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
    }

    #[test]
    fn actual_legacy_webhook_file_migrates_without_losing_signing_secret_or_retry() {
        let directory = tempfile::tempdir().unwrap();
        let current = directory.path().join("current.redb");
        let legacy = directory.path().join("legacy.redb");
        let migrated = directory.path().join("migrated.redb");
        let snapshot = {
            let store = Arc::new(RedbWebhookStore::open(&current).unwrap());
            let engine = WebhookEngine::durable(Default::default(), store.clone()).unwrap();
            engine
                .register(
                    "https://example.com/hook".into(),
                    vec!["blocks".into()],
                    Some("migration-secret".into()),
                    1,
                    0,
                )
                .unwrap();
            engine.enqueue_matches(&event(17), 0);
            assert_eq!(engine.take_due(0).len(), 1);
            store.load().unwrap().unwrap()
        };
        {
            let db = redb_legacy::Database::create(&legacy).unwrap();
            let txn = db.begin_write().unwrap();
            txn.open_table(redb_legacy::TableDefinition::<&str, &[u8]>::new(
                "webhook_snapshot_v1",
            ))
            .unwrap()
            .insert("state", snapshot.as_slice())
            .unwrap();
            txn.commit().unwrap();
        }
        let original = fs::read(&legacy).unwrap();
        #[cfg(unix)]
        let original_mode = {
            use std::os::unix::fs::PermissionsExt;
            fs::metadata(&legacy).unwrap().permissions().mode()
        };
        assert!(RedbWebhookStore::open(&legacy).is_err());
        assert!(fs::read(&legacy).unwrap() == original);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&legacy).unwrap().permissions().mode(),
                original_mode
            );
        }
        ergo_state::redb_migration::migrate_database(&legacy, &migrated).unwrap();
        let engine = WebhookEngine::durable(
            Default::default(),
            Arc::new(RedbWebhookStore::open(&migrated).unwrap()),
        )
        .unwrap();
        assert_eq!(
            engine.get("wh_0000000000000001").unwrap().secret.as_deref(),
            Some("migration-secret")
        );
        let retried = engine.take_due(u64::MAX).remove(0);
        assert_eq!(retried.delivery_id, "dl_0000000000000001");
        assert_eq!(engine.highest_event_seq(), 17);
        assert!(fs::read(&legacy).unwrap() == original);
    }

    #[test]
    fn unclean_webhook_fixture_worker() {
        let Some(path) = std::env::var_os("ERGO_WEBHOOK_UNCLEAN_FIXTURE") else {
            return;
        };
        let engine = WebhookEngine::durable(
            Default::default(),
            Arc::new(RedbWebhookStore::open(Path::new(&path)).unwrap()),
        )
        .unwrap();
        engine
            .register(
                "https://example.com/hook".into(),
                vec!["blocks".into()],
                Some("crash-secret".into()),
                1,
                0,
            )
            .unwrap();
        engine.enqueue_matches(&event(17), 0);
        assert_eq!(engine.take_due(0).len(), 1);
        // Skip every destructor to exercise recovery of the acknowledged
        // durable snapshot and reserved attempt after a real process exit.
        std::process::exit(0);
    }

    #[test]
    fn abrupt_process_exit_recovers_acknowledged_registration_and_attempt() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("webhooks.redb");
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "webhook_store::tests::unclean_webhook_fixture_worker",
            ])
            .env("ERGO_WEBHOOK_UNCLEAN_FIXTURE", &path)
            .status()
            .unwrap();
        assert!(status.success());
        let engine = WebhookEngine::durable(
            Default::default(),
            Arc::new(RedbWebhookStore::open(&path).unwrap()),
        )
        .unwrap();
        assert_eq!(
            engine.get("wh_0000000000000001").unwrap().secret.as_deref(),
            Some("crash-secret")
        );
        let retried = engine.take_due(u64::MAX).remove(0);
        assert_eq!(retried.delivery_id, "dl_0000000000000001");
        assert_eq!(
            engine.deliveries_for("wh_0000000000000001", 0, 1)[0].attempts,
            2
        );
        assert_eq!(engine.highest_event_seq(), 17);
    }
}
