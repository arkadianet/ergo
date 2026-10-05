//! CLI contract tests use the shipped binary, without loading node configuration.
use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};

use ergo_api::auth::ApiSecurity;
use serde_json::Value;

fn invoke(directory: &Path, args: &[&str], input: &[u8]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_ergo-node"))
        .current_dir(directory)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(input).unwrap();
    child.wait_with_output().unwrap()
}

fn hash(input: &[u8], json: bool) -> Output {
    let dir = tempfile::tempdir().unwrap();
    let args = if json {
        vec!["api-key", "hash", "--stdin", "--json"]
    } else {
        vec!["api-key", "hash", "--stdin"]
    };
    let output = invoke(dir.path(), &args, input);
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
    output
}

fn json_hash(output: &Output) -> String {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["schema_version"], 1);
    value["api_key_hash"].as_str().unwrap().to_owned()
}

fn assert_no_leak(output: &Output, secret: &[u8]) {
    assert!(!output.stdout.windows(secret.len()).any(|w| w == secret));
    assert!(!output.stderr.windows(secret.len()).any(|w| w == secret));
}

#[test]
fn hash_matches_independent_blake2b256_vector_and_api() {
    // Independent oracle: hashlib.blake2b(b"hello", digest_size=32).hexdigest().
    const VECTOR: &str = "324dcf027dd4a30a932c441f365a25e86b173defa4b8e58948253471b81b72cf";
    let output = hash(b"hello", true);
    assert_eq!(json_hash(&output), VECTOR);
    assert_eq!(json_hash(&output), ApiSecurity::hash_key(b"hello"));
    let json: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json.as_object().unwrap().len(), 2);
    assert_no_leak(&output, b"hello");
    let output = hash(b"hello", false);
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        format!("[api.security]\napi_key_hash = \"{VECTOR}\"\n")
    );
}

#[test]
fn generated_secret_is_random_protected_and_accepted_by_api() {
    let dir = tempfile::tempdir().unwrap();
    let directory = dir.path().canonicalize().unwrap();
    let mut previous = None;
    for name in ["first.key", "second.key"] {
        let output = invoke(
            &directory,
            &["api-key", "generate", "--secret-file", name, "--json"],
            b"",
        );
        let hash = json_hash(&output);
        let value: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(value["secret_file"], name);
        assert_eq!(value.as_object().unwrap().len(), 3);
        let bytes = fs::read(directory.join(name)).unwrap();
        assert_eq!(bytes.len(), 65);
        assert_eq!(bytes[64], b'\n');
        let secret = &bytes[..64];
        assert!(secret
            .iter()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b)));
        assert_no_leak(&output, secret);
        let security = ApiSecurity::new(hash.clone()).unwrap();
        assert!(security.verify(secret));
        assert!(security.authorize(secret, "GET", "/wallet/status", false));
        assert!(!security.verify(b"wrong-secret"));
        assert!(!security.authorize(b"wrong-secret", "GET", "/wallet/status", false));
        if let Some(previous) = previous {
            assert!(previous != bytes);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(directory.join(name))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        let rehash = invoke(
            &directory,
            &["api-key", "hash", "--secret-file", name, "--json"],
            b"",
        );
        assert_eq!(json_hash(&rehash), hash);
        assert_no_leak(&rehash, secret);
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(stderr.contains(name));
        for text in [
            "config",
            "restart",
            "secret (never the hash)",
            "api_key",
            "dashboard",
        ] {
            assert!(stderr.contains(text));
        }
        previous = Some(bytes);
    }
    assert_eq!(fs::read_dir(&directory).unwrap().count(), 2);
    assert!(!directory.join("ergo-data").exists());
    assert!(!directory.join("ergo-node.toml").exists());
}

#[test]
fn generation_toml_contains_only_configuration() {
    let dir = tempfile::tempdir().unwrap();
    let output = invoke(
        &dir.path().canonicalize().unwrap(),
        &["api-key", "generate", "--secret-file", "secret.key"],
        b"",
    );
    assert!(output.status.success());
    let bytes = fs::read(dir.path().join("secret.key")).unwrap();
    assert_no_leak(&output, &bytes[..64]);
    let expected = format!(
        "[api.security]\napi_key_hash = \"{}\"\n",
        ApiSecurity::hash_key(&bytes[..64])
    );
    assert_eq!(output.stdout, expected.as_bytes());
}

#[test]
fn hash_removes_exactly_one_lf_or_crlf_and_accepts_ascii_boundaries() {
    for input in [b"hello".as_slice(), b"hello\n", b"hello\r\n"] {
        assert_eq!(
            json_hash(&hash(input, true)),
            ApiSecurity::hash_key(b"hello")
        );
    }
    let printable: Vec<u8> = (0x21..=0x7e).collect();
    assert_eq!(
        json_hash(&hash(&printable, true)),
        ApiSecurity::hash_key(&printable)
    );
    for ending in [b"".as_slice(), b"\n", b"\r\n"] {
        let mut input = vec![b'x'; 1024];
        input.extend_from_slice(ending);
        assert_eq!(
            json_hash(&hash(&input, true)),
            ApiSecurity::hash_key(&vec![b'x'; 1024])
        );
    }
}

#[test]
fn hash_rejects_invalid_or_excess_input_without_leaking() {
    let mut invalid = vec![
        vec![],
        b"\n".to_vec(),
        b"\r\n".to_vec(),
        b"hello\r".to_vec(),
        b"hello\n\n".to_vec(),
        b"hello\r\n\n".to_vec(),
        b"hel\nlo".to_vec(),
        b"hel\rlo".to_vec(),
        b" hello".to_vec(),
        b"hello ".to_vec(),
        b"hello\t".to_vec(),
        b"hello\0".to_vec(),
        b"hello\x7f".to_vec(),
        b"hello\x80".to_vec(),
        vec![b'x'; 1025],
        vec![b'x'; 1027],
    ];
    invalid.push([vec![b'x'; 1025], b"\r\n".to_vec()].concat());
    for input in invalid {
        let output = hash(&input, true);
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        assert!(String::from_utf8_lossy(&output.stderr).contains("api-key hash <stdin>"));
        if input.len() >= 5 {
            assert_no_leak(&output, &input);
        }
    }
}

#[test]
fn usage_errors_exit_two_and_never_create_files() {
    let dir = tempfile::tempdir().unwrap();
    for args in [
        vec!["api-key"],
        vec!["api-key", "generate"],
        vec!["api-key", "hash"],
        vec!["api-key", "hash", "--stdin", "--secret-file", "key"],
        vec!["api-key", "generate", "--secret-file", "-"],
        vec!["api-key", "hash", "--secret-file", "-"],
        vec![
            "api-key",
            "generate",
            "--secret-file",
            "key",
            "--config",
            "node.toml",
        ],
    ] {
        let output = invoke(dir.path(), &args, b"");
        assert_eq!(output.status.code(), Some(2));
        if args.len() == 1 {
            assert!(String::from_utf8_lossy(&output.stderr).contains("Usage:"));
        }
    }
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
}

#[test]
fn file_errors_exit_one_and_preserve_existing_files() {
    let dir = tempfile::tempdir().unwrap();
    let directory = dir.path().canonicalize().unwrap();
    fs::write(directory.join("existing.key"), b"do-not-overwrite").unwrap();
    fs::create_dir(directory.join("existing.dir")).unwrap();
    for path in ["existing.key", "existing.dir", "missing/secret.key"] {
        let output = invoke(
            &directory,
            &["api-key", "generate", "--secret-file", path],
            b"",
        );
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        assert!(String::from_utf8_lossy(&output.stderr).contains(path.split('/').next().unwrap()));
    }
    assert_eq!(
        fs::read(directory.join("existing.key")).unwrap(),
        b"do-not-overwrite"
    );
    assert!(!directory.join("missing").exists());
    let output = invoke(
        &directory,
        &["api-key", "hash", "--secret-file", "missing.key"],
        b"",
    );
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
}

#[cfg(unix)]
#[test]
fn failed_protection_check_removes_the_new_secret_file() {
    // A umask that strips the owner's write bit makes the new file 0400, so
    // the protection check fails after creation. The command must not leave
    // an empty or partial secret file behind.
    let dir = tempfile::tempdir().unwrap();
    let output = Command::new("/bin/sh")
        .current_dir(dir.path())
        .arg("-c")
        .arg("umask 277; exec \"$0\" api-key generate --secret-file secret.key")
        .arg(env!("CARGO_BIN_EXE_ergo-node"))
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(!dir.path().join("secret.key").exists());
}

#[cfg(unix)]
#[test]
fn generation_refuses_symlinked_destinations_but_follows_symlinked_parents() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let dir = tempfile::tempdir().unwrap();
    let directory = dir.path().canonicalize().unwrap();
    fs::create_dir_all(directory.join("real/nested")).unwrap();
    fs::write(directory.join("target.key"), b"existing").unwrap();
    fs::write(directory.join("plain-file"), b"not a directory").unwrap();
    symlink("target.key", directory.join("file.link")).unwrap();
    symlink("absent.key", directory.join("dangling.link")).unwrap();
    symlink("real", directory.join("parent.link")).unwrap();
    // A symlink at the destination itself, live or dangling, and a parent
    // that is not a directory are refused without touching their targets.
    for path in ["file.link", "dangling.link", "plain-file/secret.key"] {
        let output = invoke(
            &directory,
            &["api-key", "generate", "--secret-file", path],
            b"",
        );
        assert_eq!(output.status.code(), Some(1), "{path}");
        assert!(output.stdout.is_empty());
    }
    assert_eq!(fs::read(directory.join("target.key")).unwrap(), b"existing");
    assert!(!directory.join("absent.key").exists());
    // Parents reached through symlinks are ordinary (macOS /tmp and /var, a
    // linked /home, data on another disk), so generation follows them.
    for (path, created) in [
        ("parent.link/secret.key", "real/secret.key"),
        ("parent.link/nested/secret.key", "real/nested/secret.key"),
    ] {
        let output = invoke(
            &directory,
            &["api-key", "generate", "--secret-file", path],
            b"",
        );
        assert_eq!(output.status.code(), Some(0), "{path}");
        let mode = fs::metadata(directory.join(created))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "{created}");
    }
}

#[test]
fn api_key_dispatch_precedes_runtime_and_startup_thread() {
    let source = include_str!("../../src/main.rs");
    let dispatch = source
        .find("ergo_node::api_key::run(")
        .expect("api-key dispatch must exist");
    for startup in [
        "std::thread::Builder",
        "rayon::ThreadPoolBuilder",
        "tokio::runtime::Builder",
        "init_tracing(&config.logging)",
        "NodeConfig::load(cli)",
    ] {
        assert!(dispatch < source.find(startup).unwrap());
    }
}
