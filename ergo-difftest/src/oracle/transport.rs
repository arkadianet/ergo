//! Bounded line transport for an owned oracle child.
//!
//! The deadline includes writing/flushing the request and reading its response.
//! A failed exchange is terminal: no later response can be misattributed to a
//! new request. Unix children run in an owned process group; Windows cleanup
//! covers the direct child and does not certify descendant termination.

use std::io::{self, BufRead, BufReader, Read, Write};
use std::process::{Child, Command, Stdio};
use std::sync::{mpsc, Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const MAX_LINE_BYTES: usize = 16 * 1024 * 1024;
const STDERR_PREFIX_BYTES: usize = 64 * 1024;
const STDERR_TAIL_BYTES: usize = 8 * 1024;
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Clone, Copy)]
pub(super) struct Deadlines {
    startup: Duration,
    query: Duration,
}

impl Deadlines {
    pub(super) fn from_environment() -> io::Result<Self> {
        fn deadline(name: &str, default_ms: u64) -> io::Result<Duration> {
            match std::env::var(name) {
                Ok(value) => {
                    let milliseconds = value.parse::<u64>().map_err(|_| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            format!("{name} must be an integer"),
                        )
                    })?;
                    if !(1..=1_800_000).contains(&milliseconds) {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            format!("{name} must be in 1..=1800000 milliseconds"),
                        ));
                    }
                    Ok(Duration::from_millis(milliseconds))
                }
                Err(std::env::VarError::NotPresent) => Ok(Duration::from_millis(default_ms)),
                Err(error) => Err(io::Error::new(io::ErrorKind::InvalidInput, error)),
            }
        }
        Ok(Self {
            startup: deadline("DIFFTEST_ORACLE_STARTUP_TIMEOUT_MS", 180_000)?,
            query: deadline("DIFFTEST_ORACLE_QUERY_TIMEOUT_MS", 10_000)?,
        })
    }
}

#[derive(Default)]
struct Diagnostics {
    prefix: Vec<u8>,
    tail: Vec<u8>,
    total: u64,
}

impl Diagnostics {
    fn append(&mut self, bytes: &[u8]) {
        self.total = self.total.saturating_add(bytes.len() as u64);
        let prefix_room = STDERR_PREFIX_BYTES - self.prefix.len();
        self.prefix
            .extend_from_slice(&bytes[..bytes.len().min(prefix_room)]);
        self.tail.extend_from_slice(bytes);
        let excess = self.tail.len().saturating_sub(STDERR_TAIL_BYTES);
        self.tail.drain(..excess);
    }
}

pub(super) struct Transport {
    child: Child,
    requests: Option<mpsc::SyncSender<String>>,
    responses: mpsc::Receiver<io::Result<String>>,
    worker: Option<JoinHandle<()>>,
    stderr_worker: Option<JoinHandle<()>>,
    diagnostics: Arc<Mutex<Diagnostics>>,
    deadlines: Deadlines,
    first_query: bool,
    stopped: bool,
    cleanup: String,
}

impl Transport {
    pub(super) fn spawn(mut command: Command, deadlines: Deadlines) -> io::Result<Self> {
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            command.process_group(0);
        }
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let mut stdin = child.stdin.take().expect("piped stdin");
        let mut stdout = BufReader::new(child.stdout.take().expect("piped stdout"));
        let mut stderr = child.stderr.take().expect("piped stderr");
        let (requests, request_receiver) = mpsc::sync_channel::<String>(1);
        let (response_sender, responses) = mpsc::sync_channel(1);
        let diagnostics = Arc::new(Mutex::new(Diagnostics::default()));
        let mut transport = Self {
            child,
            requests: Some(requests),
            responses,
            worker: None,
            stderr_worker: None,
            diagnostics: Arc::clone(&diagnostics),
            deadlines,
            first_query: true,
            stopped: false,
            cleanup: "child running".into(),
        };
        // Construct the owner before spawning threads: any thread-spawn failure
        // drops the owner and terminates/reaps the child.
        transport.stderr_worker = Some(thread::Builder::new().name("oracle-stderr".into()).spawn(
            move || {
                let mut buffer = [0u8; 4096];
                loop {
                    match stderr.read(&mut buffer) {
                        Ok(0) | Err(_) => break,
                        Ok(count) => diagnostics
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .append(&buffer[..count]),
                    }
                }
            },
        )?);
        transport.worker = Some(thread::Builder::new().name("oracle-lines".into()).spawn(
            move || {
                while let Ok(request) = request_receiver.recv() {
                    let result = stdin
                        .write_all(request.as_bytes())
                        .and_then(|()| stdin.write_all(b"\n"))
                        .and_then(|()| stdin.flush())
                        .and_then(|()| bounded_line(&mut stdout, MAX_LINE_BYTES));
                    let failed = result.is_err();
                    if response_sender.send(result).is_err() || failed {
                        break;
                    }
                }
            },
        )?);
        Ok(transport)
    }

    pub(super) fn pid(&self) -> u32 {
        self.child.id()
    }

    pub(super) fn stderr_prefix(&self) -> Vec<u8> {
        self.diagnostics
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .prefix
            .clone()
    }

    pub(super) fn exchange(&mut self, request: String) -> io::Result<String> {
        if self.stopped {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "oracle exchange is terminal after a previous error",
            ));
        }
        let result = if request.len() > MAX_LINE_BYTES || request.contains(['\n', '\r']) {
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "oracle request exceeds line bound or contains a newline",
            ))
        } else {
            let timeout = if self.first_query {
                self.deadlines.startup
            } else {
                self.deadlines.query
            };
            self.requests
                .as_ref()
                .expect("live sender")
                .try_send(request)
                .map_err(|error| io::Error::new(io::ErrorKind::BrokenPipe, error))
                .and_then(|()| match self.responses.recv_timeout(timeout) {
                    Ok(result) => result,
                    Err(mpsc::RecvTimeoutError::Timeout) => Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!("oracle response deadline exceeded ({timeout:?})"),
                    )),
                    Err(mpsc::RecvTimeoutError::Disconnected) => Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "oracle I/O worker closed",
                    )),
                })
        };
        match result {
            Ok(response) => {
                self.first_query = false;
                Ok(response)
            }
            Err(error) => {
                self.stop();
                let diagnostics = self.diagnostics.lock().unwrap_or_else(|e| e.into_inner());
                Err(io::Error::new(
                    error.kind(),
                    format!(
                        "{error}; {}; stderr tail ({} total bytes): {}",
                        self.cleanup,
                        diagnostics.total,
                        String::from_utf8_lossy(&diagnostics.tail)
                    ),
                ))
            }
        }
    }

    pub(super) fn stop(&mut self) {
        if self.stopped {
            return;
        }
        self.stopped = true;
        self.requests.take();
        #[cfg(unix)]
        let group_result = rustix::process::kill_process_group(
            rustix::process::Pid::from_child(&self.child),
            rustix::process::Signal::KILL,
        );
        let _ = self.child.kill();
        let deadline = Instant::now() + CLEANUP_TIMEOUT;
        let mut reaped = false;
        while Instant::now() < deadline {
            match self.child.try_wait() {
                Ok(Some(_)) => {
                    reaped = true;
                    break;
                }
                Err(_) => break,
                Ok(None) => thread::sleep(Duration::from_millis(2)),
            }
        }
        for worker in [&mut self.worker, &mut self.stderr_worker] {
            if worker.as_ref().is_some_and(JoinHandle::is_finished) {
                let _ = worker.take().expect("finished worker").join();
            }
        }
        self.cleanup = format!("direct child reaped={reaped}");
        #[cfg(unix)]
        self.cleanup
            .push_str(&format!("; owned process-group kill={group_result:?}"));
        #[cfg(windows)]
        self.cleanup
            .push_str("; descendant cleanup is not certified on Windows");
    }
}

impl Drop for Transport {
    fn drop(&mut self) {
        self.stop();
    }
}

fn bounded_line(reader: &mut impl BufRead, limit: usize) -> io::Result<String> {
    let mut line = Vec::new();
    loop {
        let bytes = reader.fill_buf()?;
        if bytes.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "oracle closed output before a complete response line",
            ));
        }
        let count = bytes
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(bytes.len(), |offset| offset + 1);
        if count > limit.saturating_sub(line.len()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "oracle response exceeds line bound",
            ));
        }
        let complete = bytes[count - 1] == b'\n';
        line.extend_from_slice(&bytes[..count]);
        reader.consume(count);
        if complete {
            return String::from_utf8(line)
                .map(|line| line.trim().to_string())
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- helpers -----

    #[cfg(unix)]
    fn test_deadlines() -> Deadlines {
        Deadlines {
            startup: Duration::from_secs(2),
            query: Duration::from_secs(2),
        }
    }

    // ----- happy path -----

    #[test]
    fn complete_lines_preserve_the_next_response() {
        let mut input = io::Cursor::new(b"ACCEPT 00\nREJECT Example\n");
        assert_eq!(bounded_line(&mut input, 64).unwrap(), "ACCEPT 00");
        assert_eq!(bounded_line(&mut input, 64).unwrap(), "REJECT Example");
    }

    #[cfg(unix)]
    #[test]
    fn owned_child_exchanges_lines_and_is_reaped() {
        let mut command = Command::new("sh");
        command.args([
            "-c",
            "while IFS= read -r line; do printf 'ACCEPT 00\\n'; done",
        ]);
        let mut transport = Transport::spawn(command, test_deadlines()).unwrap();
        assert_eq!(
            transport.exchange("ergo_tree 0008d3".into()).unwrap(),
            "ACCEPT 00"
        );
        assert_eq!(
            transport.exchange("ergo_tree 0008d3".into()).unwrap(),
            "ACCEPT 00"
        );
        transport.stop();
        assert!(transport.child.try_wait().unwrap().is_some());
        assert!(transport.cleanup.contains("reaped=true"));
    }

    // ----- error paths -----

    #[test]
    fn response_bound_and_incomplete_lines_are_errors() {
        assert_eq!(
            bounded_line(&mut io::Cursor::new(b"12345\n"), 4)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(
            bounded_line(&mut io::Cursor::new(b"ACCEPT"), 64)
                .unwrap_err()
                .kind(),
            io::ErrorKind::UnexpectedEof
        );
    }

    #[test]
    fn diagnostics_remain_bounded_and_keep_the_last_error() {
        let mut diagnostics = Diagnostics::default();
        diagnostics.append(&vec![b'a'; STDERR_PREFIX_BYTES * 2]);
        diagnostics.append(b"last diagnostic");
        assert_eq!(diagnostics.prefix.len(), STDERR_PREFIX_BYTES);
        assert_eq!(diagnostics.tail.len(), STDERR_TAIL_BYTES);
        assert!(diagnostics.tail.ends_with(b"last diagnostic"));
        assert_eq!(diagnostics.total, (STDERR_PREFIX_BYTES * 2 + 15) as u64);
    }

    #[cfg(unix)]
    #[test]
    fn harmless_wait_times_out_and_cannot_be_reused() {
        let mut command = Command::new("sh");
        command.args([
            "-c",
            "read line; printf 'waiting fixture\\n' >&2; sleep 5; printf 'ACCEPT\\n'",
        ]);
        let mut transport = Transport::spawn(
            command,
            Deadlines {
                startup: Duration::from_millis(100),
                query: Duration::from_millis(100),
            },
        )
        .unwrap();
        let started = Instant::now();
        let error = transport.exchange("ergo_tree 0008d3".into()).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(error.to_string().contains("waiting fixture"));
        assert!(started.elapsed() < Duration::from_secs(3));
        assert!(transport.child.try_wait().unwrap().is_some());
        assert_eq!(
            transport
                .exchange("ergo_tree 0008d3".into())
                .unwrap_err()
                .kind(),
            io::ErrorKind::BrokenPipe
        );
    }

    #[cfg(unix)]
    #[test]
    fn later_query_uses_its_deadline_and_reaps_the_child() {
        let mut command = Command::new("sh");
        command.args([
            "-c",
            "read line; printf 'ACCEPT 00\\n'; read line; sleep 5; printf 'ACCEPT 00\\n'",
        ]);
        let mut transport = Transport::spawn(
            command,
            Deadlines {
                startup: Duration::from_secs(2),
                query: Duration::from_millis(100),
            },
        )
        .unwrap();
        assert_eq!(transport.exchange("first".into()).unwrap(), "ACCEPT 00");
        let started = Instant::now();
        let error = transport.exchange("second".into()).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(3));
        assert!(transport.child.try_wait().unwrap().is_some());
    }

    #[cfg(unix)]
    #[test]
    fn child_eof_is_terminal_and_reaped() {
        let mut command = Command::new("sh");
        command.args(["-c", "read line; printf 'partial'"]);
        let mut transport = Transport::spawn(command, test_deadlines()).unwrap();
        assert_eq!(
            transport.exchange("first".into()).unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
        assert!(transport.child.try_wait().unwrap().is_some());
        assert_eq!(
            transport.exchange("second".into()).unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
    }
}
