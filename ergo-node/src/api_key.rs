//! Standalone API credential helpers. No config, runtime, or secret output.

use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::path::Path;

use ergo_api::auth::ApiSecurity;
use rand::{rngs::OsRng, RngCore};
use zeroize::Zeroizing;

use crate::config::ApiKeyCommand;

/// Diagnostics contain only the operation, path, and a sanitized failure reason.
#[derive(Debug, thiserror::Error)]
#[error("{message}")]
pub struct CommandError {
    code: i32,
    message: String,
}

impl CommandError {
    pub fn exit_code(&self) -> i32 {
        self.code
    }
}

type Result<T> = std::result::Result<T, CommandError>;

fn fail(code: i32, operation: &str, path: &Path, reason: &str) -> CommandError {
    CommandError {
        code,
        message: format!("api-key {operation} {}: {reason}", path.display()),
    }
}

fn io_error(operation: &str, path: &Path, error: io::Error) -> CommandError {
    // Do not propagate arbitrary reader/writer error text: it could contain input.
    fail(
        1,
        operation,
        path,
        &format!("I/O failure ({:?})", error.kind()),
    )
}

/// Run with injected streams so callers can verify that output contains no secret.
/// Input is read only in hash mode; generation always writes a protected file.
pub fn run(
    command: &ApiKeyCommand,
    stdin: &mut impl Read,
    stdout: &mut impl Write,
    stderr: &mut impl Write,
) -> Result<()> {
    match command {
        ApiKeyCommand::Generate { secret_file, json } => {
            check_destination(secret_file)?;
            let mut random = Zeroizing::new([0u8; 32]);
            OsRng
                .try_fill_bytes(random.as_mut())
                .map_err(|_| fail(1, "generate", secret_file, "OS entropy unavailable"))?;
            let mut secret = Zeroizing::new([0u8; 64]);
            // Encode directly into the protected allocation, with no String copy.
            hex::encode_to_slice(random.as_ref(), secret.as_mut())
                .expect("32 bytes encode to 64 hex bytes");
            let hash = ApiSecurity::hash_key(secret.as_ref());
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options
                .open(secret_file)
                .map_err(|e| io_error("create", secret_file, e))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = file
                    .metadata()
                    .map_err(|e| io_error("check protection", secret_file, e))?
                    .permissions()
                    .mode()
                    & 0o777;
                if mode != 0o600 {
                    return Err(fail(
                        1,
                        "check protection",
                        secret_file,
                        "expected mode 0600",
                    ));
                }
            }
            file.write_all(secret.as_ref())
                .and_then(|()| file.write_all(b"\n"))
                .and_then(|()| file.flush())
                .and_then(|()| file.sync_all())
                .map_err(|e| io_error("write and sync", secret_file, e))?;
            print_hash(stdout, &hash, Some(secret_file), *json)?;
            writeln!(stderr, "Secret file: {}", secret_file.display())
                .map_err(|e| io_error("report", secret_file, e))?;
            #[cfg(windows)]
            writeln!(
                stderr,
                "Windows uses inherited ACLs; keep the secret in a directory only you can read."
            )
            .map_err(|e| io_error("report", secret_file, e))?;
            guidance(stderr, secret_file)
        }
        ApiKeyCommand::Hash {
            secret_file, json, ..
        } => {
            let source = secret_file.as_deref().unwrap_or(Path::new("<stdin>"));
            let hash = if let Some(path) = secret_file {
                if path == Path::new("-") {
                    return Err(fail(2, "hash", path, "use --stdin to read stdin"));
                }
                let mut file = fs::File::open(path).map_err(|e| io_error("read", path, e))?;
                read_hash(&mut file, source)?
            } else {
                read_hash(stdin, source)?
            };
            print_hash(stdout, &hash, None, *json)?;
            guidance(stderr, source)
        }
    }
}

fn check_destination(path: &Path) -> Result<()> {
    if path == Path::new("-") || path.file_name().is_none() {
        return Err(fail(
            2,
            "generate",
            path,
            "a secret file path is required; stdout is forbidden",
        ));
    }
    match fs::symlink_metadata(path) {
        Ok(_) => {
            return Err(fail(
                1,
                "create",
                path,
                "destination already exists (symlinks are forbidden)",
            ))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(io_error("check destination", path, e)),
    }
    // Check every ancestor, including lexical components before `..`, so a
    // symlink hidden higher in the path cannot bypass the parent check.
    for ancestor in path.ancestors().skip(1) {
        let ancestor = if ancestor.as_os_str().is_empty() {
            Path::new(".")
        } else {
            ancestor
        };
        let metadata =
            fs::symlink_metadata(ancestor).map_err(|e| io_error("check parent", ancestor, e))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(fail(
                1,
                "check parent",
                ancestor,
                "parent must be an existing directory, without symlinks",
            ));
        }
    }
    Ok(())
}

fn read_hash(reader: &mut impl Read, source: &Path) -> Result<String> {
    // 1024 secret bytes + CRLF + one lookahead byte to detect excess input.
    // A fixed buffer avoids leaving old secret allocations behind on growth.
    let mut input = Zeroizing::new([0u8; 1027]);
    let mut len = 0;
    while len < input.len() {
        match reader.read(&mut input[len..]) {
            Ok(0) => break,
            Ok(n) => len += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(io_error("read", source, e)),
        }
    }
    if len > 1026 {
        return Err(fail(
            2,
            "hash",
            source,
            "input exceeds 1024 bytes plus a line ending",
        ));
    }
    if len > 0 && input[len - 1] == b'\n' {
        len -= 1;
        if len > 0 && input[len - 1] == b'\r' {
            len -= 1;
        }
    }
    if len == 0 || len > 1024 || !input[..len].iter().all(|b| (0x21..=0x7e).contains(b)) {
        return Err(fail(2, "hash", source, "secret must be 1..=1024 printable non-space ASCII bytes with at most one trailing LF or CRLF"));
    }
    Ok(ApiSecurity::hash_key(&input[..len]))
}

fn print_hash(
    stdout: &mut impl Write,
    hash: &str,
    secret_file: Option<&Path>,
    json: bool,
) -> Result<()> {
    let output = if json {
        let mut value = serde_json::json!({"schema_version": 1, "api_key_hash": hash});
        if let Some(path) = secret_file {
            value["secret_file"] = serde_json::json!(path.to_string_lossy());
        }
        format!("{value}\n")
    } else {
        format!("[api.security]\napi_key_hash = \"{hash}\"\n")
    };
    stdout
        .write_all(output.as_bytes())
        .and_then(|()| stdout.flush())
        .map_err(|e| io_error("print hash", Path::new("<stdout>"), e))
}

fn guidance(stderr: &mut impl Write, source: &Path) -> Result<()> {
    writeln!(stderr, "Add this to your config, restart the node, and send the secret (never the hash) in the api_key header or enter it in the dashboard.")
        .map_err(|e| io_error("report", source, e))
}
