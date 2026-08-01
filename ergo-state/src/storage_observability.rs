use std::collections::{hash_map::Entry, HashMap};
use std::error::Error;
use std::hash::Hash;
use std::io;
use std::path::Path;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const DEFAULT_SUMMARY_INTERVAL: Duration = Duration::from_secs(300);
const DEFAULT_FAILURE_CAPACITY: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum StorageErrorClass {
    Io,
    PreviousIo,
    Other,
}

impl StorageErrorClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Io => "io",
            Self::PreviousIo => "previous_io",
            Self::Other => "other",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorDiagnostics {
    pub class: StorageErrorClass,
    pub display: String,
    pub debug: String,
    pub chain: String,
    pub io_kind: Option<String>,
    pub raw_os_error: Option<i32>,
}

impl ErrorDiagnostics {
    pub fn from_error(error: &(dyn Error + 'static)) -> Self {
        let mut chain = Vec::new();
        let mut class = StorageErrorClass::Other;
        let mut io_kind = None;
        let mut raw_os_error = None;
        let mut current = Some(error);

        while let Some(item) = current {
            push_unique(&mut chain, item.to_string());
            match classify_redb_error(item) {
                Some(RedbFailure::Io(io_error)) if class != StorageErrorClass::PreviousIo => {
                    class = StorageErrorClass::Io;
                    io_kind = Some(format!("{:?}", io_error.kind()));
                    raw_os_error = io_error.raw_os_error();
                    push_unique(
                        &mut chain,
                        format!(
                            "io::Error(kind={:?}, raw_os_error={:?}): {io_error}",
                            io_error.kind(),
                            io_error.raw_os_error()
                        ),
                    );
                }
                Some(RedbFailure::PreviousIo) => {
                    class = StorageErrorClass::PreviousIo;
                    io_kind = None;
                    raw_os_error = None;
                }
                _ => {}
            }
            current = item.source();
        }

        Self {
            class,
            display: error.to_string(),
            debug: format!("{error:?}"),
            chain: chain.join(" -> "),
            io_kind,
            raw_os_error,
        }
    }

    pub fn is_poisoned(&self) -> bool {
        self.class == StorageErrorClass::PreviousIo
    }
}

fn push_unique(chain: &mut Vec<String>, value: String) {
    if chain.last() != Some(&value) {
        chain.push(value);
    }
}

enum RedbFailure<'a> {
    Io(&'a io::Error),
    PreviousIo,
}

fn classify_storage_error(error: &redb::StorageError) -> Option<RedbFailure<'_>> {
    match error {
        redb::StorageError::Io(io_error) => Some(RedbFailure::Io(io_error)),
        redb::StorageError::PreviousIo => Some(RedbFailure::PreviousIo),
        _ => None,
    }
}

fn classify_redb_error<'a>(error: &'a (dyn Error + 'static)) -> Option<RedbFailure<'a>> {
    if let Some(error) = error.downcast_ref::<redb::StorageError>() {
        return classify_storage_error(error);
    }
    if let Some(error) = error.downcast_ref::<Box<redb::StorageError>>() {
        return classify_storage_error(error);
    }

    macro_rules! classify_wrapped {
        ($ty:ty, $pattern:pat => $storage:expr) => {
            if let Some($pattern) = error.downcast_ref::<$ty>() {
                return classify_storage_error($storage);
            }
            if let Some($pattern) = error.downcast_ref::<Box<$ty>>().map(Box::as_ref) {
                return classify_storage_error($storage);
            }
        };
    }

    classify_wrapped!(
        redb::TransactionError,
        redb::TransactionError::Storage(storage) => storage
    );
    classify_wrapped!(
        redb::CommitError,
        redb::CommitError::Storage(storage) => storage
    );
    classify_wrapped!(
        redb::TableError,
        redb::TableError::Storage(storage) => storage
    );
    classify_wrapped!(
        redb::DatabaseError,
        redb::DatabaseError::Storage(storage) => storage
    );

    if let Some(error) = error.downcast_ref::<redb::Error>() {
        return classify_general_redb_error(error);
    }
    if let Some(error) = error.downcast_ref::<Box<redb::Error>>() {
        return classify_general_redb_error(error);
    }
    None
}

fn classify_general_redb_error(error: &redb::Error) -> Option<RedbFailure<'_>> {
    match error {
        redb::Error::Io(io_error) => Some(RedbFailure::Io(io_error)),
        redb::Error::PreviousIo => Some(RedbFailure::PreviousIo),
        _ => None,
    }
}

#[derive(Debug, Clone, Copy)]
pub struct StorageFailureContext<'a> {
    pub subsystem: &'static str,
    pub component: &'static str,
    pub database_path: Option<&'a Path>,
    pub operation: &'static str,
    pub best_full_block_height: Option<u32>,
    pub best_header_height: Option<u32>,
    pub attempted_height: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageHealth {
    Healthy,
    Degraded,
    IoFailed,
    Poisoned,
}

impl StorageHealth {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Degraded => "degraded",
            Self::IoFailed => "io_failed",
            Self::Poisoned => "poisoned",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageHealthTransition {
    pub previous: StorageHealth,
    pub current: StorageHealth,
    pub initiating_io_observed: bool,
    pub initiating_io_operation: Option<String>,
    pub initiating_io_raw_os_error: Option<i32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageSummary {
    pub suppressed_count: u64,
    pub first_seen_unix_ms: u64,
    pub last_seen_unix_ms: u64,
    pub elapsed_ms: u64,
    pub subsystem: String,
    pub component: String,
    pub database_path: Option<String>,
    pub operation: String,
    pub error_class: StorageErrorClass,
    pub error: String,
    pub best_full_block_height: Option<u32>,
    pub best_header_height: Option<u32>,
    pub attempted_height: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StorageReport {
    First {
        diagnostics: ErrorDiagnostics,
        health_transition: Option<StorageHealthTransition>,
    },
    Suppressed,
    Summary(StorageSummary),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StorageHealthSnapshot {
    pub health: StorageHealth,
    pub io_failures_total: u64,
    pub previous_io_failures_total: u64,
    pub suppressed_total: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct FailureKey {
    subsystem: String,
    component: String,
    database_path: Option<String>,
    operation: String,
    error_class: StorageErrorClass,
}

struct FailureEntry {
    last_emit_unix_ms: u64,
    suppressed_count: u64,
    first_suppressed_unix_ms: Option<u64>,
    last_seen_unix_ms: u64,
    last_access_sequence: u64,
    first_error: String,
}

struct InitiatingIo {
    operation: String,
    raw_os_error: Option<i32>,
}

struct ReporterState {
    failures: HashMap<FailureKey, FailureEntry>,
    health: StorageHealth,
    first_io: Option<InitiatingIo>,
    io_failures_total: u64,
    previous_io_failures_total: u64,
    suppressed_total: u64,
    access_sequence: u64,
}

impl Default for ReporterState {
    fn default() -> Self {
        Self {
            failures: HashMap::new(),
            health: StorageHealth::Healthy,
            first_io: None,
            io_failures_total: 0,
            previous_io_failures_total: 0,
            suppressed_total: 0,
            access_sequence: 0,
        }
    }
}

pub struct StorageFailureReporter {
    summary_interval_ms: u64,
    failure_capacity: usize,
    state: Mutex<ReporterState>,
}

impl StorageFailureReporter {
    pub fn new(summary_interval: Duration) -> Self {
        Self {
            summary_interval_ms: summary_interval.as_millis().min(u64::MAX as u128) as u64,
            failure_capacity: DEFAULT_FAILURE_CAPACITY,
            state: Mutex::new(ReporterState::default()),
        }
    }

    pub fn record_at(
        &self,
        context: &StorageFailureContext<'_>,
        error: &(dyn Error + 'static),
        now: SystemTime,
    ) -> StorageReport {
        let now_unix_ms = unix_ms(now);
        let diagnostics = ErrorDiagnostics::from_error(error);
        let key = FailureKey {
            subsystem: context.subsystem.to_string(),
            component: context.component.to_string(),
            database_path: context.database_path.map(|path| path.display().to_string()),
            operation: context.operation.to_string(),
            error_class: diagnostics.class,
        };
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        let health_transition = update_health(&mut state, context, &diagnostics);
        let access_sequence = state.access_sequence;
        state.access_sequence = state.access_sequence.saturating_add(1);

        if state.failures.len() >= self.failure_capacity && !state.failures.contains_key(&key) {
            let oldest = state
                .failures
                .iter()
                .min_by(|(left_key, left), (right_key, right)| {
                    left.last_access_sequence
                        .cmp(&right.last_access_sequence)
                        .then_with(|| left_key.cmp(right_key))
                })
                .map(|(key, _)| key.clone());
            if let Some(oldest) = oldest {
                state.failures.remove(&oldest);
            }
        }

        let report = match state.failures.entry(key) {
            Entry::Vacant(entry) => {
                entry.insert(FailureEntry {
                    last_emit_unix_ms: now_unix_ms,
                    suppressed_count: 0,
                    first_suppressed_unix_ms: None,
                    last_seen_unix_ms: now_unix_ms,
                    last_access_sequence: access_sequence,
                    first_error: diagnostics.display.clone(),
                });
                return StorageReport::First {
                    diagnostics,
                    health_transition,
                };
            }
            Entry::Occupied(mut occupied) => {
                let entry = occupied.get_mut();
                entry.suppressed_count = entry.suppressed_count.saturating_add(1);
                entry.first_suppressed_unix_ms.get_or_insert(now_unix_ms);
                entry.last_seen_unix_ms = now_unix_ms;
                entry.last_access_sequence = access_sequence;

                if now_unix_ms.saturating_sub(entry.last_emit_unix_ms) < self.summary_interval_ms {
                    StorageReport::Suppressed
                } else {
                    let first_seen_unix_ms = entry.first_suppressed_unix_ms.unwrap_or(now_unix_ms);
                    let suppressed_count = entry.suppressed_count;
                    let last_seen_unix_ms = entry.last_seen_unix_ms;
                    let error = entry.first_error.clone();
                    entry.last_emit_unix_ms = now_unix_ms;
                    entry.suppressed_count = 0;
                    entry.first_suppressed_unix_ms = None;

                    let key = occupied.key();
                    StorageReport::Summary(StorageSummary {
                        suppressed_count,
                        first_seen_unix_ms,
                        last_seen_unix_ms,
                        elapsed_ms: last_seen_unix_ms.saturating_sub(first_seen_unix_ms),
                        subsystem: key.subsystem.clone(),
                        component: key.component.clone(),
                        database_path: key.database_path.clone(),
                        operation: key.operation.clone(),
                        error_class: key.error_class,
                        error,
                        best_full_block_height: context.best_full_block_height,
                        best_header_height: context.best_header_height,
                        attempted_height: context.attempted_height,
                    })
                }
            }
        };

        state.suppressed_total = state.suppressed_total.saturating_add(1);
        report
    }

    pub fn report_at(
        &self,
        context: &StorageFailureContext<'_>,
        error: &(dyn Error + 'static),
        now: SystemTime,
    ) -> StorageReport {
        let report = self.record_at(context, error, now);
        emit_report(context, &report);
        report
    }

    pub fn report(
        &self,
        context: &StorageFailureContext<'_>,
        error: &(dyn Error + 'static),
    ) -> StorageReport {
        self.report_at(context, error, SystemTime::now())
    }

    pub fn health_snapshot(&self) -> StorageHealthSnapshot {
        let state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        StorageHealthSnapshot {
            health: state.health,
            io_failures_total: state.io_failures_total,
            previous_io_failures_total: state.previous_io_failures_total,
            suppressed_total: state.suppressed_total,
        }
    }
}

fn update_health(
    state: &mut ReporterState,
    context: &StorageFailureContext<'_>,
    diagnostics: &ErrorDiagnostics,
) -> Option<StorageHealthTransition> {
    match diagnostics.class {
        StorageErrorClass::Io => {
            state.io_failures_total = state.io_failures_total.saturating_add(1);
            if state.first_io.is_none() {
                state.first_io = Some(InitiatingIo {
                    operation: context.operation.to_string(),
                    raw_os_error: diagnostics.raw_os_error,
                });
            }
            if state.health != StorageHealth::Poisoned {
                state.health = StorageHealth::IoFailed;
            }
            None
        }
        StorageErrorClass::PreviousIo => {
            state.previous_io_failures_total = state.previous_io_failures_total.saturating_add(1);
            if state.health == StorageHealth::Poisoned {
                return None;
            }
            let previous = state.health;
            state.health = StorageHealth::Poisoned;
            Some(StorageHealthTransition {
                previous,
                current: StorageHealth::Poisoned,
                initiating_io_observed: state.first_io.is_some(),
                initiating_io_operation: state
                    .first_io
                    .as_ref()
                    .map(|first| first.operation.clone()),
                initiating_io_raw_os_error: state
                    .first_io
                    .as_ref()
                    .and_then(|first| first.raw_os_error),
            })
        }
        StorageErrorClass::Other => {
            if state.health == StorageHealth::Healthy {
                state.health = StorageHealth::Degraded;
            }
            None
        }
    }
}

fn emit_report(context: &StorageFailureContext<'_>, report: &StorageReport) {
    match report {
        StorageReport::First {
            diagnostics,
            health_transition,
        } => {
            let event = if health_transition.is_some() {
                "storage_health_transition"
            } else if diagnostics.class == StorageErrorClass::Io {
                "storage_io_failure"
            } else {
                "storage_operation_failed"
            };
            let transition = health_transition.as_ref();
            let storage_health =
                transition
                    .map(|value| value.current)
                    .unwrap_or_else(|| match diagnostics.class {
                        StorageErrorClass::Io => StorageHealth::IoFailed,
                        StorageErrorClass::PreviousIo => StorageHealth::Poisoned,
                        StorageErrorClass::Other => StorageHealth::Degraded,
                    });
            tracing::error!(
                event,
                subsystem = context.subsystem,
                component = context.component,
                database_path = %context.database_path.map(Path::display).map(|path| path.to_string()).unwrap_or_default(),
                database_path_available = context.database_path.is_some(),
                operation = context.operation,
                error = %diagnostics.display,
                error_debug = %diagnostics.debug,
                error_chain = %diagnostics.chain,
                error_class = diagnostics.class.as_str(),
                io_kind = diagnostics.io_kind.as_deref().unwrap_or_default(),
                io_kind_available = diagnostics.io_kind.is_some(),
                raw_os_error = diagnostics.raw_os_error.unwrap_or_default(),
                raw_os_error_available = diagnostics.raw_os_error.is_some(),
                storage_health = storage_health.as_str(),
                handle_usable = storage_health != StorageHealth::Poisoned,
                previous_storage_health = transition.map(|value| value.previous.as_str()).unwrap_or_default(),
                initiating_io_observed = transition.map(|value| value.initiating_io_observed).unwrap_or(false),
                initiating_io_operation = transition.and_then(|value| value.initiating_io_operation.as_deref()).unwrap_or_default(),
                initiating_io_raw_os_error = transition.and_then(|value| value.initiating_io_raw_os_error).unwrap_or_default(),
                initiating_io_raw_os_error_available = transition.and_then(|value| value.initiating_io_raw_os_error).is_some(),
                best_full_block_height = context.best_full_block_height.unwrap_or_default(),
                best_full_block_height_available = context.best_full_block_height.is_some(),
                best_header_height = context.best_header_height.unwrap_or_default(),
                best_header_height_available = context.best_header_height.is_some(),
                attempted_height = context.attempted_height.unwrap_or_default(),
                attempted_height_available = context.attempted_height.is_some(),
                "storage operation failed",
            );
        }
        StorageReport::Summary(summary) => {
            tracing::warn!(
                event = "storage_error_summary",
                subsystem = summary.subsystem,
                component = summary.component,
                database_path = summary.database_path.as_deref().unwrap_or_default(),
                database_path_available = summary.database_path.is_some(),
                operation = summary.operation,
                error = summary.error,
                error_class = summary.error_class.as_str(),
                suppressed_count = summary.suppressed_count,
                first_seen_unix_ms = summary.first_seen_unix_ms,
                last_seen_unix_ms = summary.last_seen_unix_ms,
                elapsed_ms = summary.elapsed_ms,
                best_full_block_height = summary.best_full_block_height.unwrap_or_default(),
                best_full_block_height_available = summary.best_full_block_height.is_some(),
                best_header_height = summary.best_header_height.unwrap_or_default(),
                best_header_height_available = summary.best_header_height.is_some(),
                attempted_height = summary.attempted_height.unwrap_or_default(),
                attempted_height_available = summary.attempted_height.is_some(),
                "repeated storage failures suppressed",
            );
        }
        StorageReport::Suppressed => {}
    }
}

fn unix_ms(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u64::MAX as u128) as u64
}

fn global_reporter() -> &'static StorageFailureReporter {
    static REPORTER: OnceLock<StorageFailureReporter> = OnceLock::new();
    REPORTER.get_or_init(|| StorageFailureReporter::new(DEFAULT_SUMMARY_INTERVAL))
}

pub fn report_storage_failure(
    context: &StorageFailureContext<'_>,
    error: &(dyn Error + 'static),
) -> StorageReport {
    global_reporter().report(context, error)
}

pub fn storage_health_snapshot() -> StorageHealthSnapshot {
    global_reporter().health_snapshot()
}
