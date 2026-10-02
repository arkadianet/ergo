//! Private durable webhook snapshot store. Signing secrets are stored in the
//! operator data directory; restrict this database to the operator account.
use ergo_api::v1::webhooks::engine::WebhookStore;
use std::path::Path;

const SNAPSHOT: redb::TableDefinition<&str, &[u8]> =
    redb::TableDefinition::new("webhook_snapshot_v1");

pub(crate) struct RedbWebhookStore {
    db: redb::Database,
}

impl RedbWebhookStore {
    pub(crate) fn open(path: &Path) -> Result<Self, String> {
        let mut options = std::fs::OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(path).map_err(|e| e.to_string())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(std::fs::Permissions::from_mode(0o600))
                .map_err(|e| e.to_string())?;
        }
        drop(file);
        Ok(Self {
            db: redb::Database::create(path).map_err(|e| e.to_string())?,
        })
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
        let write = self.db.begin_write().map_err(|e| e.to_string())?;
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

    #[test]
    fn webhook_database_corrupt_snapshot_refuses_startup() {
        let directory = tempfile::tempdir().unwrap();
        let store =
            Arc::new(RedbWebhookStore::open(&directory.path().join("webhooks.redb")).unwrap());
        store.commit(b"not a snapshot").unwrap();
        assert!(WebhookEngine::durable(Default::default(), store).is_err());
    }
}
