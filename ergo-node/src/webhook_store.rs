//! Private durable webhook snapshot store. Signing secrets are stored in the
//! operator data directory; restrict this database to the operator account.
use ergo_api::v1::webhooks::engine::WebhookStore;
use redb::{ReadableDatabase, ReadableTable, ReadableTableMetadata};
use std::fs::{self, OpenOptions};
use std::path::Path;

// One bounded snapshot table does not need another 1 GiB page cache. This
// limits redb's clean-page cache, not JSON snapshot allocations or process RSS.
const CACHE_BYTES: usize = 16 * 1024 * 1024;

const SNAPSHOT: redb::TableDefinition<&str, &[u8]> =
    redb::TableDefinition::new("webhook_snapshot_v1");

const REALTIME_EVENTS: redb::TableDefinition<u64, &[u8]> =
    redb::TableDefinition::new("realtime_events_v1");
const REALTIME_META: redb::TableDefinition<&str, &[u8]> =
    redb::TableDefinition::new("realtime_metadata_v1");

#[derive(serde::Serialize, serde::Deserialize)]
struct RealtimeMetadata {
    version: u32,
    next_seq: u64,
    retained_bytes: u64,
}

impl Default for RealtimeMetadata {
    fn default() -> Self {
        Self {
            version: 1,
            next_seq: 1,
            retained_bytes: 0,
        }
    }
}

// One-shot faults stay local to each test thread and do not exist in production.
#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum OpenFault {
    Metadata,
    FileSync,
    CreateRace,
}

#[cfg(test)]
thread_local! {
    static OPEN_FAULT: std::cell::Cell<Option<OpenFault>> = const { std::cell::Cell::new(None) };
}

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
        #[cfg(test)]
        let fault = OPEN_FAULT.with(std::cell::Cell::take);
        #[cfg(test)]
        if fault == Some(OpenFault::CreateRace) {
            fs::write(path, b"raced initializer").map_err(|e| e.to_string())?;
        }
        // An unsuccessful create_new must never enter cleanup: another
        // initializer may have won the race and owns the existing file.
        let file = options.open(path).map_err(|e| e.to_string())?;
        let initialized = (|| {
            #[cfg(test)]
            if fault == Some(OpenFault::Metadata) {
                return Err("injected webhook metadata failure".into());
            }
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
            #[cfg(test)]
            if fault == Some(OpenFault::FileSync) {
                return Err("injected webhook file-sync failure".into());
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
        })();
        // The closure owns every file/database handle. They have all dropped
        // on Err before removal, including on Windows where open handles can
        // prevent unlinking. Existing files remain available for diagnosis.
        if created && initialized.is_err() {
            if let Err(error) = fs::remove_file(path) {
                tracing::warn!(%error, "failed to remove newly-created webhook database after initialization error");
            }
        }
        initialized
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

impl ergo_api::v1::realtime::journal::RealtimeStore for RedbWebhookStore {
    fn load_events(&self) -> Result<ergo_api::v1::realtime::journal::JournalRecovery, String> {
        use ergo_api::v1::realtime::journal::{JournalRecovery, JOURNAL_BYTES_CAP};
        let read = self.db.begin_read().map_err(|e| e.to_string())?;
        let metadata = match read.open_table(REALTIME_META) {
            Ok(table) => table
                .get("state")
                .map_err(|e| e.to_string())?
                .map(|value| serde_json::from_slice::<RealtimeMetadata>(value.value()))
                .transpose()
                .map_err(|e| e.to_string())?
                .unwrap_or_default(),
            Err(redb::TableError::TableDoesNotExist(_)) => RealtimeMetadata::default(),
            Err(error) => return Err(error.to_string()),
        };
        if metadata.version != 1
            || metadata.next_seq == 0
            || metadata.retained_bytes > JOURNAL_BYTES_CAP as u64
        {
            return Err("invalid realtime metadata".into());
        }
        let mut recovery = JournalRecovery {
            next_seq: metadata.next_seq,
            events: Vec::new(),
        };
        let table = match read.open_table(REALTIME_EVENTS) {
            Ok(table) => table,
            Err(redb::TableError::TableDoesNotExist(_)) if metadata.retained_bytes == 0 => {
                return Ok(recovery)
            }
            Err(error) => return Err(error.to_string()),
        };
        if table.len().map_err(|e| e.to_string())?
            > ergo_api::v1::realtime::bus::RESUME_WINDOW as u64
        {
            return Err("realtime event retention exceeds limit".into());
        }
        let mut bytes = 0u64;
        for entry in table.iter().map_err(|e| e.to_string())? {
            let (key, value) = entry.map_err(|e| e.to_string())?;
            bytes = bytes
                .checked_add(value.value().len() as u64)
                .ok_or("realtime byte count overflow")?;
            if bytes > JOURNAL_BYTES_CAP as u64 {
                return Err("realtime event retention exceeds byte limit".into());
            }
            let event: ergo_api::v1::realtime::journal::ReplayEvent =
                serde_json::from_slice(value.value()).map_err(|e| e.to_string())?;
            if event.seq != key.value() || event.seq >= metadata.next_seq {
                return Err("realtime cursor/key mismatch".into());
            }
            recovery.events.push(event);
        }
        if bytes != metadata.retained_bytes {
            return Err("realtime retained byte count mismatch".into());
        }
        Ok(recovery)
    }

    fn reserve_cursor(&self, next_seq: u64) -> Result<(), String> {
        if next_seq == 0 || next_seq >= u64::MAX - 1 {
            return Err("realtime cursor exhausted".into());
        }
        let mut write = ergo_state::begin_write_qr(&self.db).map_err(|e| e.to_string())?;
        write
            .set_durability(redb::Durability::Immediate)
            .map_err(|e| e.to_string())?;
        {
            let events = write
                .open_table(REALTIME_EVENTS)
                .map_err(|e| e.to_string())?;
            if events
                .last()
                .map_err(|e| e.to_string())?
                .is_some_and(|(key, _)| key.value() >= next_seq)
            {
                return Err("realtime reservation precedes persisted events".into());
            }
            let mut table = write.open_table(REALTIME_META).map_err(|e| e.to_string())?;
            let mut metadata = table
                .get("state")
                .map_err(|e| e.to_string())?
                .map(|value| serde_json::from_slice::<RealtimeMetadata>(value.value()))
                .transpose()
                .map_err(|e| e.to_string())?
                .unwrap_or_default();
            if metadata.version != 1 {
                return Err("unsupported realtime metadata".into());
            }
            metadata.next_seq = next_seq;
            let bytes = serde_json::to_vec(&metadata).map_err(|e| e.to_string())?;
            table
                .insert("state", bytes.as_slice())
                .map_err(|e| e.to_string())?;
        }
        write.commit().map_err(|e| e.to_string())
    }

    fn append_events(
        &self,
        events: &[ergo_api::v1::realtime::journal::ReplayEvent],
    ) -> Result<(), String> {
        use ergo_api::v1::realtime::journal::{JOURNAL_BYTES_CAP, JOURNAL_EVENT_BYTES_CAP};
        let mut batch_bytes = 0;
        let encoded = events
            .iter()
            .map(|event| {
                let bytes = serde_json::to_vec(event).map_err(|e| e.to_string())?;
                if bytes.len() > JOURNAL_EVENT_BYTES_CAP {
                    return Err("realtime event exceeds byte limit".into());
                }
                batch_bytes += bytes.len();
                if batch_bytes > JOURNAL_BYTES_CAP {
                    return Err("realtime batch exceeds byte limit".into());
                }
                Ok((event.seq, bytes))
            })
            .collect::<Result<Vec<_>, String>>()?;
        let mut write = ergo_state::begin_write_qr(&self.db).map_err(|e| e.to_string())?;
        write
            .set_durability(redb::Durability::Immediate)
            .map_err(|e| e.to_string())?;
        {
            let mut metadata_table = write.open_table(REALTIME_META).map_err(|e| e.to_string())?;
            let mut metadata = metadata_table
                .get("state")
                .map_err(|e| e.to_string())?
                .map(|value| serde_json::from_slice::<RealtimeMetadata>(value.value()))
                .transpose()
                .map_err(|e| e.to_string())?
                .ok_or("realtime cursor was not reserved")?;
            let mut table = write
                .open_table(REALTIME_EVENTS)
                .map_err(|e| e.to_string())?;
            let mut last = table
                .last()
                .map_err(|e| e.to_string())?
                .map(|(key, _)| key.value())
                .unwrap_or(0);
            for (seq, bytes) in encoded {
                if seq <= last || seq >= metadata.next_seq {
                    return Err("realtime event outside reserved cursor range".into());
                }
                table
                    .insert(seq, bytes.as_slice())
                    .map_err(|e| e.to_string())?;
                metadata.retained_bytes = metadata
                    .retained_bytes
                    .checked_add(bytes.len() as u64)
                    .ok_or("realtime byte count overflow")?;
                last = seq;
            }
            while table.len().map_err(|e| e.to_string())?
                > ergo_api::v1::realtime::bus::RESUME_WINDOW as u64
                || metadata.retained_bytes > JOURNAL_BYTES_CAP as u64
            {
                let (key, size) = table
                    .first()
                    .map_err(|e| e.to_string())?
                    .map(|(key, value)| (key.value(), value.value().len() as u64))
                    .ok_or("realtime retention accounting mismatch")?;
                table.remove(key).map_err(|e| e.to_string())?;
                metadata.retained_bytes = metadata
                    .retained_bytes
                    .checked_sub(size)
                    .ok_or("realtime byte count underflow")?;
            }
            let bytes = serde_json::to_vec(&metadata).map_err(|e| e.to_string())?;
            metadata_table
                .insert("state", bytes.as_slice())
                .map_err(|e| e.to_string())?;
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
    fn realtime_database_reopen_preserves_history_cursor_and_retention() {
        use ergo_api::v1::realtime::bus::RESUME_WINDOW;
        use ergo_api::v1::realtime::journal::{RealtimeStore, ReplayEvent};
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("webhooks.redb");
        let store = RedbWebhookStore::open(&path).unwrap();
        store.reserve_cursor(20_000).unwrap();
        let events = (1..=(RESUME_WINDOW as u64 + 3))
            .map(|seq| ReplayEvent::from(&event(seq)))
            .collect::<Vec<_>>();
        store.append_events(&events).unwrap();
        drop(store);
        let store = RedbWebhookStore::open(&path).unwrap();
        let saved = store.load_events().unwrap();
        assert_eq!(saved.next_seq, 20_000);
        assert_eq!(saved.events.len(), RESUME_WINDOW);
        assert_eq!(saved.events[0].seq, 4);
        assert_eq!(saved.events.last().unwrap().seq, RESUME_WINDOW as u64 + 3);
        assert!(store.reserve_cursor(10).is_err());
        assert!(store
            .append_events(&[ReplayEvent::from(&event(20_000))])
            .is_err());
        assert_eq!(store.load_events().unwrap().events.len(), RESUME_WINDOW);
    }

    #[test]
    fn oversized_realtime_append_rolls_back_entire_batch() {
        use ergo_api::v1::realtime::journal::{
            RealtimeStore, ReplayEvent, JOURNAL_EVENT_BYTES_CAP,
        };
        let directory = tempfile::tempdir().unwrap();
        let store = RedbWebhookStore::open(&directory.path().join("webhooks.redb")).unwrap();
        store.reserve_cursor(100).unwrap();
        let mut oversized = ReplayEvent::from(&event(2));
        oversized.data = serde_json::json!({"large": "x".repeat(JOURNAL_EVENT_BYTES_CAP)});
        assert!(store
            .append_events(&[ReplayEvent::from(&event(1)), oversized])
            .is_err());
        assert!(store.load_events().unwrap().events.is_empty());
    }

    #[test]
    fn oversized_realtime_batch_rolls_back_before_writing() {
        use ergo_api::v1::realtime::journal::{RealtimeStore, ReplayEvent};
        let directory = tempfile::tempdir().unwrap();
        let store = RedbWebhookStore::open(&directory.path().join("webhooks.redb")).unwrap();
        store.reserve_cursor(1000).unwrap();
        let events = (1..=140)
            .map(|seq| {
                let mut event = ReplayEvent::from(&event(seq));
                event.data = serde_json::json!({"large": "x".repeat(512 * 1024)});
                event
            })
            .collect::<Vec<_>>();
        assert_eq!(
            store.append_events(&events).unwrap_err(),
            "realtime batch exceeds byte limit"
        );
        assert!(store.load_events().unwrap().events.is_empty());
        assert_eq!(store.load_events().unwrap().next_seq, 1000);
    }

    #[tokio::test]
    async fn restart_admits_unqueued_durable_events_and_persists_delivery_ack() {
        use ergo_api::v1::realtime::{ChannelClass, RealtimeBus, RealtimeEventBody};
        use ergo_api::v1::webhooks::worker::{spawn_webhook_worker_with_shutdown, WebhookSink};
        use ergo_api::v1::webhooks::PreparedRequest;
        use std::time::Duration;
        struct Sink {
            seen: std::sync::Mutex<Vec<PreparedRequest>>,
            notify: tokio::sync::Notify,
        }
        #[async_trait::async_trait]
        impl WebhookSink for Sink {
            async fn post(&self, request: &PreparedRequest) -> DeliveryOutcome {
                self.seen.lock().unwrap().push(request.clone());
                self.notify.notify_one();
                DeliveryOutcome::Success(204)
            }
        }
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("webhooks.redb");
        let store = Arc::new(RedbWebhookStore::open(&path).unwrap());
        let engine = WebhookEngine::durable(Default::default(), store.clone()).unwrap();
        let subscription = engine
            .register_after(
                "https://receiver.example/hook".into(),
                vec!["blocks".into()],
                Some("key".into()),
                1,
                0,
                0,
            )
            .unwrap();
        let bus = RealtimeBus::durable(
            [ChannelClass::Blocks].into_iter().collect(),
            store.clone(),
            1,
        )
        .unwrap();
        bus.publish(RealtimeEventBody::block_applied(
            1,
            "header".into(),
            1,
            1,
            100,
        ));
        drop(bus); // persist source observation before any worker admission
        drop(engine);
        drop(store);

        let store = Arc::new(RedbWebhookStore::open(&path).unwrap());
        let engine = Arc::new(WebhookEngine::durable(Default::default(), store.clone()).unwrap());
        assert_eq!(engine.replay_seq(), 0);
        let bus = Arc::new(
            RealtimeBus::durable(
                [ChannelClass::Blocks].into_iter().collect(),
                store.clone(),
                1,
            )
            .unwrap(),
        );
        let sink = Arc::new(Sink {
            seen: Default::default(),
            notify: Default::default(),
        });
        let (stop, signal) = tokio::sync::oneshot::channel();
        let worker = spawn_webhook_worker_with_shutdown(
            bus.clone(),
            engine.clone(),
            sink.clone(),
            Duration::from_millis(1),
            signal,
        );
        tokio::time::timeout(Duration::from_secs(3), sink.notify.notified())
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(3), async {
            while engine.deliveries_for(&subscription.webhook_id, 0, 1)[0].status
                != ergo_api::v1::webhooks::model::DeliveryStatus::Delivered
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        stop.send(()).unwrap();
        worker.await.unwrap();
        assert_eq!(sink.seen.lock().unwrap().len(), 1);
        assert_eq!(engine.replay_seq(), 1);
        drop(bus);
        drop(engine);
        drop(store);
        let engine = WebhookEngine::durable(
            Default::default(),
            Arc::new(RedbWebhookStore::open(&path).unwrap()),
        )
        .unwrap();
        assert!(engine.take_due(u64::MAX).is_empty());
        assert_eq!(
            engine.deliveries_for(&subscription.webhook_id, 0, 10).len(),
            1
        );
    }

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
    fn failed_new_initialization_releases_handles_removes_file_and_allows_retry() {
        for (fault, expected) in [
            (OpenFault::Metadata, "injected webhook metadata failure"),
            (OpenFault::FileSync, "injected webhook file-sync failure"),
        ] {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("webhooks.redb");
            OPEN_FAULT.with(|injection| injection.set(Some(fault)));
            assert_eq!(RedbWebhookStore::open(&path).err().unwrap(), expected);
            assert_eq!(
                fs::symlink_metadata(&path).unwrap_err().kind(),
                std::io::ErrorKind::NotFound,
                "a failed new initialization must not poison the next startup"
            );
            assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 0);
            // The late fault runs with a real redb database and cloned handle
            // alive. Immediate removal/retry also checks their Windows cleanup.
            let store = RedbWebhookStore::open(&path).unwrap();
            store.commit(b"acknowledged after retry").unwrap();
            drop(store);
            let reopened = RedbWebhookStore::open(&path).unwrap();
            assert_eq!(
                reopened.load().unwrap().unwrap(),
                b"acknowledged after retry"
            );
        }
    }

    #[test]
    fn initialization_errors_never_remove_an_existing_snapshot() {
        for (fault, expected) in [
            (OpenFault::Metadata, "injected webhook metadata failure"),
            (OpenFault::FileSync, "injected webhook file-sync failure"),
        ] {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("webhooks.redb");
            let store = RedbWebhookStore::open(&path).unwrap();
            store.commit(b"existing acknowledged snapshot").unwrap();
            drop(store);
            OPEN_FAULT.with(|injection| injection.set(Some(fault)));
            assert_eq!(RedbWebhookStore::open(&path).err().unwrap(), expected);
            assert!(path.is_file());
            let reopened = RedbWebhookStore::open(&path).unwrap();
            assert_eq!(
                reopened.load().unwrap().unwrap(),
                b"existing acknowledged snapshot"
            );
        }
    }

    #[test]
    fn losing_create_new_race_never_removes_the_winning_initializers_file() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("webhooks.redb");
        OPEN_FAULT.with(|injection| injection.set(Some(OpenFault::CreateRace)));
        assert!(RedbWebhookStore::open(&path).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"raced initializer");
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
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
    fn unclean_replay_fixture_worker() {
        use ergo_api::v1::realtime::journal::RealtimeStore;
        use ergo_api::v1::realtime::{ChannelClass, RealtimeBus, RealtimeEventBody};
        let Some(path) = std::env::var_os("ERGO_REPLAY_UNCLEAN_FIXTURE") else {
            return;
        };
        let store = Arc::new(RedbWebhookStore::open(Path::new(&path)).unwrap());
        let engine = WebhookEngine::durable(Default::default(), store.clone()).unwrap();
        engine
            .register_after(
                "https://receiver.example/hook".into(),
                vec!["blocks".into()],
                Some("crash-key".into()),
                1,
                0,
                0,
            )
            .unwrap();
        let bus = RealtimeBus::durable(
            [ChannelClass::Blocks].into_iter().collect(),
            store.clone(),
            1,
        )
        .unwrap();
        for height in 1..=10 {
            bus.publish(RealtimeEventBody::block_applied(
                1,
                format!("h-{height}"),
                height,
                1,
                100,
            ));
        }
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while store.load_events().unwrap().events.len() < 10 {
            assert!(std::time::Instant::now() < deadline);
            std::thread::yield_now();
        }
        for observation in bus.backfill(&["blocks".into()].into(), 0, 5).events {
            engine.enqueue_matches(&observation, 0);
        }
        engine.checkpoint_replay(5);
        // Real abrupt exit: retain ten source records, five admissions and the
        // unused journal reservation without invoking any destructor.
        std::process::exit(0);
    }

    #[tokio::test]
    async fn abrupt_exit_with_lagging_worker_admits_retained_prefix_before_gap() {
        use ergo_api::v1::realtime::journal::RealtimeStore;
        use ergo_api::v1::realtime::{ChannelClass, RealtimeBus};
        use ergo_api::v1::webhooks::worker::{spawn_webhook_worker_with_shutdown, WebhookSink};
        use ergo_api::v1::webhooks::PreparedRequest;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::time::Duration;
        #[derive(Default)]
        struct Sink(AtomicUsize);
        #[async_trait::async_trait]
        impl WebhookSink for Sink {
            async fn post(&self, _: &PreparedRequest) -> DeliveryOutcome {
                self.0.fetch_add(1, Ordering::SeqCst);
                DeliveryOutcome::Success(204)
            }
        }
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("webhooks.redb");
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "webhook_store::tests::unclean_replay_fixture_worker",
            ])
            .env("ERGO_REPLAY_UNCLEAN_FIXTURE", &path)
            .status()
            .unwrap();
        assert!(status.success());
        let store = Arc::new(RedbWebhookStore::open(&path).unwrap());
        let before_gap = store.load_events().unwrap().next_seq - 1;
        let engine = Arc::new(WebhookEngine::durable(Default::default(), store.clone()).unwrap());
        let hook = engine.list(0, 1).remove(0).webhook_id;
        let original = engine.deliveries_for(&hook, 0, 20);
        assert_eq!(original.len(), 5);
        let bus = Arc::new(
            RealtimeBus::durable(
                [ChannelClass::Blocks].into_iter().collect(),
                store.clone(),
                6,
            )
            .unwrap(),
        );
        let sink = Arc::new(Sink::default());
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let worker = spawn_webhook_worker_with_shutdown(
            bus.clone(),
            engine.clone(),
            sink.clone(),
            Duration::from_millis(1),
            stopped,
        );
        tokio::time::timeout(Duration::from_secs(5), async {
            while engine.replay_seq() < before_gap {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        stop.send(()).unwrap();
        worker.await.unwrap();
        bus.shutdown_journal().await;
        let admitted = engine.deliveries_for(&hook, 0, 20);
        assert_eq!(
            admitted.len(),
            10,
            "retained events 6..10 must survive crash catch-up"
        );
        for delivery in original {
            assert!(admitted
                .iter()
                .any(|after| after.delivery_id == delivery.delivery_id
                    && after.event_seq == delivery.event_seq));
        }
        assert!(!engine.get(&hook).unwrap().active);
        assert_eq!(
            sink.0.load(Ordering::SeqCst),
            0,
            "gap pauses outbound attempts while keeping obligations"
        );
        drop(engine);
        let recovered = WebhookEngine::durable(Default::default(), store).unwrap();
        assert_eq!(recovered.replay_seq(), before_gap);
        assert_eq!(recovered.deliveries_for(&hook, 0, 20).len(), 10);
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
