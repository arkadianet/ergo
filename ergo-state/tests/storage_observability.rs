use std::error::Error;
use std::fmt;
use std::io;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, UNIX_EPOCH};

use ergo_state::storage_observability::{
    ErrorDiagnostics, StorageErrorClass, StorageFailureContext, StorageFailureReporter,
    StorageHealth, StorageReport,
};
use ergo_state::store::StateError;
use tracing_subscriber::fmt::MakeWriter;

#[derive(Debug)]
struct IncidentError {
    source: StateError,
}

impl fmt::Display for IncidentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("state persistence incident")
    }
}

impl Error for IncidentError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.source)
    }
}

fn io_incident(errno: i32) -> IncidentError {
    IncidentError {
        source: StateError::TransactionError(Box::new(redb::TransactionError::Storage(
            redb::StorageError::Io(io::Error::from_raw_os_error(errno)),
        ))),
    }
}

fn previous_io_incident() -> IncidentError {
    IncidentError {
        source: StateError::TransactionError(Box::new(redb::TransactionError::Storage(
            redb::StorageError::PreviousIo,
        ))),
    }
}

#[derive(Debug)]
struct DynamicFailure {
    height: u32,
    id: &'static str,
}

impl fmt::Display for DynamicFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "page write failed at height {} for {}",
            self.height, self.id
        )
    }
}

impl Error for DynamicFailure {}

fn context(operation: &'static str) -> StorageFailureContext<'static> {
    StorageFailureContext {
        subsystem: "state",
        component: "persist_worker",
        database_path: Some(Path::new("/var/lib/ergo/state.redb")),
        operation,
        best_full_block_height: Some(1_234),
        best_header_height: Some(1_240),
        attempted_height: None,
    }
}

#[test]
fn dynamic_error_values_share_identity_but_boundaries_and_classes_do_not() {
    let reporter = StorageFailureReporter::new(Duration::from_secs(30));
    let first = DynamicFailure {
        height: 1_000,
        id: "header-a",
    };
    let same_failure = DynamicFailure {
        height: 1_001,
        id: "header-b",
    };

    assert!(matches!(
        reporter.record_at(&context("write_page"), &first, UNIX_EPOCH),
        StorageReport::First { .. }
    ));
    assert!(matches!(
        reporter.record_at(
            &context("write_page"),
            &same_failure,
            UNIX_EPOCH + Duration::from_secs(1)
        ),
        StorageReport::Suppressed
    ));

    assert!(matches!(
        reporter.record_at(
            &context("commit"),
            &same_failure,
            UNIX_EPOCH + Duration::from_secs(2)
        ),
        StorageReport::First { .. }
    ));

    let mut other_component = context("write_page");
    other_component.component = "header_store";
    assert!(matches!(
        reporter.record_at(
            &other_component,
            &same_failure,
            UNIX_EPOCH + Duration::from_secs(3)
        ),
        StorageReport::First { .. }
    ));

    assert!(matches!(
        reporter.record_at(
            &context("write_page"),
            &previous_io_incident(),
            UNIX_EPOCH + Duration::from_secs(4)
        ),
        StorageReport::First { .. }
    ));
}

#[test]
fn reporter_capacity_uses_lru_eviction() {
    const CAPACITY: usize = 128;
    let reporter = StorageFailureReporter::new(Duration::from_secs(300));
    let error = DynamicFailure {
        height: 1,
        id: "stable",
    };
    let operations: Vec<&'static str> = (0..=CAPACITY)
        .map(|index| Box::leak(format!("operation-{index}").into_boxed_str()) as &'static str)
        .collect();

    for (index, operation) in operations.iter().take(CAPACITY).enumerate() {
        assert!(matches!(
            reporter.record_at(
                &context(operation),
                &error,
                UNIX_EPOCH + Duration::from_millis(index as u64)
            ),
            StorageReport::First { .. }
        ));
    }

    assert!(matches!(
        reporter.record_at(
            &context(operations[0]),
            &error,
            UNIX_EPOCH + Duration::from_secs(1)
        ),
        StorageReport::Suppressed
    ));
    assert!(matches!(
        reporter.record_at(
            &context(operations[CAPACITY]),
            &error,
            UNIX_EPOCH + Duration::from_secs(2)
        ),
        StorageReport::First { .. }
    ));

    assert!(matches!(
        reporter.record_at(
            &context(operations[0]),
            &error,
            UNIX_EPOCH + Duration::from_secs(3)
        ),
        StorageReport::Suppressed
    ));
    assert!(matches!(
        reporter.record_at(
            &context(operations[1]),
            &error,
            UNIX_EPOCH + Duration::from_secs(4)
        ),
        StorageReport::First { .. }
    ));
}

#[test]
fn diagnostics_nested_redb_io_retains_errno_kind_and_chain() {
    let error = io_incident(13);

    let diagnostics = ErrorDiagnostics::from_error(&error);

    assert_eq!(diagnostics.class, StorageErrorClass::Io);
    assert_eq!(diagnostics.io_kind.as_deref(), Some("PermissionDenied"));
    assert_eq!(diagnostics.raw_os_error, Some(13));
    assert!(diagnostics.chain.contains("state persistence incident"));
    assert!(diagnostics.chain.contains("redb transaction error"));
    assert!(diagnostics.chain.contains("Permission denied"));
}

#[test]
fn diagnostics_nested_previous_io_classifies_poisoned_handle() {
    let diagnostics = ErrorDiagnostics::from_error(&previous_io_incident());

    assert_eq!(diagnostics.class, StorageErrorClass::PreviousIo);
    assert!(diagnostics.is_poisoned());
    assert_eq!(diagnostics.io_kind, None);
    assert_eq!(diagnostics.raw_os_error, None);
}

#[test]
fn reporter_repeats_are_suppressed_then_summarized_with_exact_count() {
    let reporter = StorageFailureReporter::new(Duration::from_secs(5));
    let error = previous_io_incident();

    assert!(matches!(
        reporter.record_at(&context("commit"), &error, UNIX_EPOCH),
        StorageReport::First { .. }
    ));
    assert!(matches!(
        reporter.record_at(
            &context("commit"),
            &error,
            UNIX_EPOCH + Duration::from_secs(1)
        ),
        StorageReport::Suppressed
    ));
    assert!(matches!(
        reporter.record_at(
            &context("commit"),
            &error,
            UNIX_EPOCH + Duration::from_secs(2)
        ),
        StorageReport::Suppressed
    ));

    let report = reporter.record_at(
        &context("commit"),
        &error,
        UNIX_EPOCH + Duration::from_secs(5),
    );
    let StorageReport::Summary(summary) = report else {
        panic!("expected periodic summary");
    };
    assert_eq!(summary.suppressed_count, 3);
    assert_eq!(summary.first_seen_unix_ms, 1_000);
    assert_eq!(summary.last_seen_unix_ms, 5_000);
    assert_eq!(summary.elapsed_ms, 4_000);
    assert_eq!(summary.operation, "commit");
    assert_eq!(summary.best_full_block_height, Some(1_234));
    assert_eq!(summary.best_header_height, Some(1_240));
}

#[test]
fn reporter_previous_io_transitions_health_and_links_first_io() {
    let reporter = StorageFailureReporter::new(Duration::from_secs(30));
    let io_error = io_incident(13);
    let previous_io = previous_io_incident();

    reporter.record_at(&context("write_pages"), &io_error, UNIX_EPOCH);
    let report = reporter.record_at(
        &context("begin_write"),
        &previous_io,
        UNIX_EPOCH + Duration::from_secs(1),
    );

    let StorageReport::First {
        health_transition: Some(transition),
        ..
    } = report
    else {
        panic!("PreviousIo must emit a health transition");
    };
    assert_eq!(transition.previous, StorageHealth::IoFailed);
    assert_eq!(transition.current, StorageHealth::Poisoned);
    assert!(transition.initiating_io_observed);
    assert_eq!(
        transition.initiating_io_operation.as_deref(),
        Some("write_pages")
    );
    assert_eq!(transition.initiating_io_raw_os_error, Some(13));

    let health = reporter.health_snapshot();
    assert_eq!(health.health, StorageHealth::Poisoned);
    assert_eq!(health.io_failures_total, 1);
    assert_eq!(health.previous_io_failures_total, 1);
}

#[derive(Clone)]
struct SharedBuf(Arc<Mutex<Vec<u8>>>);

struct SharedWriter(Arc<Mutex<Vec<u8>>>);

impl io::Write for SharedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for SharedBuf {
    type Writer = SharedWriter;

    fn make_writer(&'a self) -> Self::Writer {
        SharedWriter(self.0.clone())
    }
}

#[test]
fn reporter_emits_stable_structured_first_io_and_poison_transition_fields() {
    let writer = SharedBuf(Arc::new(Mutex::new(Vec::new())));
    let subscriber = tracing_subscriber::fmt()
        .json()
        .with_ansi(false)
        .with_target(false)
        .with_writer(writer.clone())
        .finish();
    let reporter = StorageFailureReporter::new(Duration::from_secs(30));

    tracing::subscriber::with_default(subscriber, || {
        reporter.report_at(&context("write_pages"), &io_incident(13), UNIX_EPOCH);
        reporter.report_at(
            &context("begin_write"),
            &previous_io_incident(),
            UNIX_EPOCH + Duration::from_secs(1),
        );
        reporter.report_at(
            &context("write_pages"),
            &io_incident(13),
            UNIX_EPOCH + Duration::from_secs(31),
        );
    });

    let output = String::from_utf8(writer.0.lock().unwrap().clone()).unwrap();
    let events: Vec<serde_json::Value> = output
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(events.len(), 3);

    let io_fields = &events[0]["fields"];
    assert_eq!(io_fields["event"], "storage_io_failure");
    assert_eq!(io_fields["subsystem"], "state");
    assert_eq!(io_fields["component"], "persist_worker");
    assert_eq!(io_fields["database_path"], "/var/lib/ergo/state.redb");
    assert_eq!(io_fields["operation"], "write_pages");
    assert_eq!(io_fields["error_class"], "io");
    assert_eq!(io_fields["io_kind"], "PermissionDenied");
    assert_eq!(io_fields["raw_os_error"], 13);
    assert_eq!(io_fields["best_full_block_height"], 1_234);
    assert_eq!(io_fields["best_header_height"], 1_240);
    assert!(io_fields["error_chain"]
        .as_str()
        .unwrap()
        .contains("Permission denied"));

    let poisoned_fields = &events[1]["fields"];
    assert_eq!(poisoned_fields["event"], "storage_health_transition");
    assert_eq!(poisoned_fields["storage_health"], "poisoned");
    assert_eq!(poisoned_fields["handle_usable"], false);
    assert_eq!(poisoned_fields["initiating_io_observed"], true);
    assert_eq!(poisoned_fields["initiating_io_operation"], "write_pages");
    assert_eq!(poisoned_fields["initiating_io_raw_os_error"], 13);

    let summary_fields = &events[2]["fields"];
    assert_eq!(summary_fields["event"], "storage_error_summary");
    assert_eq!(summary_fields["operation"], "write_pages");
    assert_eq!(summary_fields["suppressed_count"], 1);
    assert_eq!(summary_fields["first_seen_unix_ms"], 31_000);
    assert_eq!(summary_fields["last_seen_unix_ms"], 31_000);
    assert_eq!(summary_fields["best_full_block_height"], 1_234);
    assert_eq!(summary_fields["best_header_height"], 1_240);
}
