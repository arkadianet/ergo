//! Sealed start: the daemon holds no key until a password (or passphrase)
//! releases the wallet database key, and only then opens `wallet.redb`.
//!
//! States, for both modes:
//! - **Sealed**: after start, before the first unseal. No key is in memory,
//!   the database is not opened and nothing syncs. The local API serves
//!   lifecycle status, unseal/unlock and seal; everything else is
//!   `503 wallet_sealed`.
//! - **Unsealed**: the database key is held by the encrypted backend, so sync,
//!   balances, history and job following run. A seed wallet may still be
//!   locked: auto-lock wipes only the spending key.
//!
//! Seed wallets keep the database key sealed in the keystore under the wallet
//! password. Watch-only wallets keep it in `data-key.json`, sealed under an
//! operator passphrase. `[security] unseal_key_file` (for example a systemd
//! `LoadCredentialEncrypted=` credential bound to the TPM) unseals at start
//! without a password; that copy of the key is only as strong as its
//! storage.
use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::extract::{DefaultBodyLimit, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use ergo_wallet::error::WalletError;
use ergo_wallet::storage::SecretStorage;
use ergo_wallet_protocol::{WalletAdminError, WalletErrorSurface};
use ergo_wallet_service::engine::UnlockThrottle;
use ergo_wallet_service::{RedbWalletStore, WalletService};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::chain_http::HttpChainClient;
use crate::config::{ApiKey, Config, ConfigError, WalletMode};
use crate::encrypted_db::{self, DataKey, EncryptedDbError};
use crate::host::{FileAttemptJournal, SpendingCapabilities, WalletHost, UNLOCK_ATTEMPTS_FILE};
use crate::spending::RemoteSpendingAccess;
use crate::sync::{StandaloneSyncer, SyncConfig};
use crate::tip::CachedNodeTip;
use crate::DaemonError;

/// Watch-only database key file, sealed under the operator passphrase.
pub const WATCH_KEY_FILE: &str = "data-key.json";
const WALLET_DB: &str = "wallet.redb";
const MAX_SECRET_BODY: usize = 16 * 1024;

/// The services that exist once the database is open.
#[derive(Clone)]
pub struct Opened {
    pub(crate) service: Arc<WalletService>,
    pub(crate) syncer: Arc<StandaloneSyncer>,
    pub(crate) host: Option<WalletHost>,
}

/// Everything needed to open the database, kept while sealed.
pub(crate) struct OpenContext {
    pub(crate) config: Config,
    /// `None` only for daemons assembled already open (tests).
    pub(crate) chain: Option<Arc<HttpChainClient>>,
    pub(crate) tip: Arc<CachedNodeTip>,
}

fn secret_dir(config: &Config) -> PathBuf {
    config.data_dir.join("wallet")
}

fn store_error(error: impl std::fmt::Display) -> DaemonError {
    DaemonError::Server(format!("wallet database: {error}"))
}

/// Open `wallet.redb` with `key`, creating it when absent and encrypting a
/// cleartext database in place (verified copy, then atomic rename).
fn open_database(data_dir: &Path, key: &DataKey) -> Result<redb::Database, DaemonError> {
    let path = data_dir.join(WALLET_DB);
    let pending = data_dir.join(format!("{WALLET_DB}.encrypting"));
    if pending.exists() {
        // An interrupted conversion; its source is still complete.
        std::fs::remove_file(&pending)?;
    }
    match encrypted_db::open_database(&path, key) {
        Err(EncryptedDbError::Cleartext) => {
            encrypted_db::encrypt_file(&path, &pending, key).map_err(store_error)?;
            std::fs::rename(&pending, &path)?;
            #[cfg(unix)]
            std::fs::File::open(data_dir)?.sync_all()?;
            tracing::info!(
                "wallet database encrypted; its former cleartext blocks may remain on disk until overwritten"
            );
            encrypted_db::open_database(&path, key).map_err(store_error)
        }
        Err(EncryptedDbError::WrongKey) => Err(DaemonError::Server(
            "wallet.redb is encrypted with a different key than this wallet's".to_string(),
        )),
        other => other.map_err(store_error),
    }
}

/// Build the services over the database opened with `key`. `new_wallet` is
/// the key a later `init`/`restore` must seal into the new keystore.
pub(crate) fn open(
    context: &OpenContext,
    key: &DataKey,
    new_wallet: bool,
) -> Result<Opened, DaemonError> {
    let config = &context.config;
    let chain = context
        .chain
        .clone()
        .ok_or_else(|| DaemonError::Server("no node client to open the wallet with".into()))?;
    let db = open_database(&config.data_dir, key)?;
    let mut store = RedbWalletStore::from_standalone_db(Arc::new(db))?;
    if config.mode == WalletMode::Seed {
        store = store.rebuild_history_on_key_additions();
    }
    let store = Arc::new(store);
    if config.mode == WalletMode::WatchOnly {
        let path = config.descriptor_file.as_deref().ok_or_else(|| {
            ConfigError::Invalid("watch_only mode requires descriptor_file".into())
        })?;
        let descriptors = crate::descriptor::parse_file(path, config.network)?;
        crate::descriptor::import(store.as_ref(), &descriptors)?;
    }
    let service = Arc::new(WalletService::new(store.clone(), chain.clone()));
    let host = if config.mode == WalletMode::Seed {
        let spending = Arc::new(RemoteSpendingAccess::new(
            store.clone(),
            chain,
            config.network,
        ));
        let host = WalletHost::with_spending(
            store.clone(),
            service.clone(),
            SpendingCapabilities {
                chain: spending.clone(),
                preparation: spending.clone(),
                submitter: spending.clone(),
                mempool: spending,
            },
            &config.data_dir,
            config.network,
        )?;
        if new_wallet {
            host.set_new_wallet_data_key(key);
        }
        if config.multisig_nonces == crate::config::NonceHolder::Daemon {
            host.enable_nonce_custody();
        }
        Some(host)
    } else {
        None
    };
    let syncer = Arc::new(StandaloneSyncer::new(
        service.clone(),
        SyncConfig {
            batch: config.sync_batch,
            page: config.blocks_page,
            ..SyncConfig::default()
        },
        context.tip.clone(),
    ));
    Ok(Opened {
        service,
        syncer,
        host,
    })
}

/// How the daemon starts.
pub(crate) enum Start {
    /// Unsealed at start: an unseal key file, or a seed directory with no
    /// wallet yet (its fresh database key is sealed by `init`/`restore`).
    Open(Opened),
    /// Waiting for a password or passphrase.
    Sealed,
}

/// Decide the start state, opening the database when no secret is needed.
pub(crate) fn start(context: &OpenContext) -> Result<Start, DaemonError> {
    let config = &context.config;
    if let Some(path) = &config.unseal_key_file {
        let key = read_unseal_key_file(path)?;
        let new_wallet = config.mode == WalletMode::Seed && !keystore_exists(config)?;
        return open(context, &key, new_wallet).map(Start::Open);
    }
    if config.mode == WalletMode::Seed && !keystore_exists(config)? {
        // No wallet yet. A database sealed by a key that never reached a
        // keystore is unreadable by construction; set it aside.
        let path = config.data_dir.join(WALLET_DB);
        if path.exists() && !is_cleartext(&path)? {
            let aside = config.data_dir.join(format!(
                "{WALLET_DB}.orphaned-{}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |elapsed| elapsed.as_secs())
            ));
            tracing::warn!(
                aside = %aside.display(),
                "encrypted wallet.redb without a keystore cannot be opened; set aside"
            );
            std::fs::rename(&path, &aside)?;
        }
        return open(context, &DataKey::generate(), true).map(Start::Open);
    }
    Ok(Start::Sealed)
}

fn keystore_exists(config: &Config) -> Result<bool, DaemonError> {
    match SecretStorage::find_secret_file(&secret_dir(config)) {
        Ok(_) => Ok(true),
        Err(WalletError::WalletUninitialized) => Ok(false),
        Err(error) => Err(crate::host::HostError::from(error).into()),
    }
}

fn is_cleartext(path: &Path) -> Result<bool, DaemonError> {
    let mut prefix = [0u8; 4];
    use std::io::Read;
    let read = std::fs::File::open(path)?.read(&mut prefix)?;
    Ok(read == 4 && &prefix == b"redb")
}

/// Recover the database key with the wallet password (seed) or passphrase
/// (watch-only), for `ergo-walletd export-unseal-key`. Never creates a key.
pub fn export_unseal_key(config: &Config, secret: &str) -> Result<DataKey, DaemonError> {
    match config.mode {
        WalletMode::Seed => match SecretStorage::open_data_key(&secret_dir(config), secret) {
            Ok(Some(key)) => Ok(DataKey::from_bytes(*key)),
            Ok(None) => Err(DaemonError::Server(
                "the wallet has no database key yet; unlock it once in the daemon first".into(),
            )),
            Err(WalletError::Decryption) => Err(DaemonError::Server("wrong password".into())),
            Err(error) => Err(crate::host::HostError::from(error).into()),
        },
        WalletMode::WatchOnly => {
            if !config.data_dir.join(WATCH_KEY_FILE).exists() {
                return Err(DaemonError::Server(
                    "the wallet has no database key yet; unseal it once in the daemon first".into(),
                ));
            }
            watch_data_key(&config.data_dir, secret).map_err(|error| match error {
                WalletAdminError::WrongPassword => DaemonError::Server("wrong passphrase".into()),
                other => DaemonError::Server(other.to_string()),
            })
        }
    }
}

/// Read a raw 32-byte database key, hex-encoded, from an owner-only file.
pub fn read_unseal_key_file(path: &Path) -> Result<DataKey, DaemonError> {
    let text = crate::config::read_api_key(path)?;
    let bytes =
        Zeroizing::new(hex::decode(text.expose()).map_err(|_| {
            ConfigError::Invalid("unseal_key_file must hold 64 hex characters".into())
        })?);
    let key: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| ConfigError::Invalid("unseal_key_file must hold 64 hex characters".into()))?;
    Ok(DataKey::from_bytes(key))
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WatchKeyFile {
    version: u32,
    kdf: ergo_wallet::storage::KdfV2,
    iv: String,
    #[serde(rename = "cipherText")]
    cipher_text: String,
}

fn watch_key_aad(
    params: ergo_wallet::encryption::Argon2idParams,
    salt: &[u8],
    iv: &[u8; 12],
) -> Vec<u8> {
    let mut aad = b"ergo-walletd watch data key v1\0".to_vec();
    aad.extend_from_slice(&params.memory_kib.to_be_bytes());
    aad.extend_from_slice(&params.iterations.to_be_bytes());
    aad.extend_from_slice(&params.parallelism.to_be_bytes());
    aad.extend_from_slice(salt);
    aad.extend_from_slice(iv);
    aad
}

/// Unwrap the watch-only database key, or create it on the first unseal.
fn watch_data_key(data_dir: &Path, passphrase: &str) -> Result<DataKey, WalletAdminError> {
    let internal = |error: String| WalletAdminError::Internal(error);
    let path = data_dir.join(WATCH_KEY_FILE);
    match std::fs::read(&path) {
        Ok(bytes) => {
            let file: WatchKeyFile =
                serde_json::from_slice(&bytes).map_err(|error| internal(error.to_string()))?;
            if file.version != 1 || file.kdf.algorithm != "argon2id" {
                return Err(internal("unsupported data-key.json".into()));
            }
            let params = ergo_wallet::encryption::Argon2idParams {
                memory_kib: file.kdf.memory_kib,
                iterations: file.kdf.iterations,
                parallelism: file.kdf.parallelism,
            };
            let salt = hex::decode(&file.kdf.salt).map_err(|error| internal(error.to_string()))?;
            let iv: [u8; 12] = hex::decode(&file.iv)
                .ok()
                .and_then(|iv| iv.try_into().ok())
                .ok_or_else(|| internal("data-key.json iv".into()))?;
            let sealed =
                hex::decode(&file.cipher_text).map_err(|error| internal(error.to_string()))?;
            let kek =
                ergo_wallet::encryption::derive_key_argon2id(passphrase.as_bytes(), &salt, params)
                    .map_err(|error| internal(error.to_string()))?;
            let plain = ergo_wallet::encryption::open(
                &kek,
                &iv,
                &sealed,
                &watch_key_aad(params, &salt, &iv),
            )
            .map_err(|_| WalletAdminError::WrongPassword)?;
            let key: [u8; 32] = plain
                .as_slice()
                .try_into()
                .map_err(|_| internal("data-key.json key length".into()))?;
            Ok(DataKey::from_bytes(key))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if passphrase.chars().count() < 12 {
                return Err(WalletAdminError::BadRequest(
                    "a watch-only passphrase needs at least 12 characters".into(),
                ));
            }
            let key = DataKey::generate();
            let params = ergo_wallet::storage::new_keystore_kdf();
            let mut salt = [0u8; 32];
            let mut iv = [0u8; 12];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut salt);
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut iv);
            let kek =
                ergo_wallet::encryption::derive_key_argon2id(passphrase.as_bytes(), &salt, params)
                    .map_err(|error| internal(error.to_string()))?;
            let sealed = ergo_wallet::encryption::seal(
                &kek,
                &iv,
                key.expose(),
                &watch_key_aad(params, &salt, &iv),
            )
            .map_err(|error| internal(error.to_string()))?;
            let file = WatchKeyFile {
                version: 1,
                kdf: ergo_wallet::storage::KdfV2 {
                    algorithm: "argon2id".into(),
                    memory_kib: params.memory_kib,
                    iterations: params.iterations,
                    parallelism: params.parallelism,
                    salt: hex::encode(salt),
                },
                iv: hex::encode(iv),
                cipher_text: hex::encode(sealed),
            };
            write_private_new(
                &path,
                &serde_json::to_vec_pretty(&file).expect("serializable"),
            )
            .map_err(|error| internal(error.to_string()))?;
            Ok(key)
        }
        Err(error) => Err(internal(error.to_string())),
    }
}

/// Create an owner-only file durably; never replaces an existing one.
fn write_private_new(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let mut pending = tempfile::Builder::new()
        .prefix(".data-key-")
        .tempfile_in(dir)?;
    pending.write_all(bytes)?;
    pending.as_file().sync_all()?;
    pending
        .persist_noclobber(path)
        .map_err(|error| error.error)?;
    #[cfg(unix)]
    std::fs::File::open(dir)?.sync_all()?;
    Ok(())
}

/// Shared state of a sealed daemon's API.
/// Installs the unsealed API before an unseal request is answered.
pub(crate) type RouterInstaller = Box<dyn Fn(&Opened) + Send + Sync>;

pub(crate) struct Gate {
    context: OpenContext,
    installer: std::sync::OnceLock<RouterInstaller>,
    opened: tokio::sync::Mutex<Option<Opened>>,
    throttle: parking_lot::Mutex<UnlockThrottle>,
    unsealed: tokio::sync::mpsc::UnboundedSender<Opened>,
    seal: tokio::sync::watch::Sender<bool>,
}

impl Gate {
    pub(crate) fn new(
        context: OpenContext,
        opened: Option<Opened>,
        unsealed: tokio::sync::mpsc::UnboundedSender<Opened>,
        seal: tokio::sync::watch::Sender<bool>,
    ) -> Arc<Self> {
        let journal = Arc::new(FileAttemptJournal(
            context.config.data_dir.join(UNLOCK_ATTEMPTS_FILE),
        ));
        Arc::new(Self {
            context,
            installer: std::sync::OnceLock::new(),
            opened: tokio::sync::Mutex::new(opened),
            throttle: parking_lot::Mutex::new(UnlockThrottle::new(journal)),
            unsealed,
            seal,
        })
    }

    /// Set how an unseal installs the unsealed API. Set once, before serving.
    pub(crate) fn set_installer(&self, installer: RouterInstaller) {
        let _ = self.installer.set(installer);
    }

    /// Release the database key with `secret` and open the database, unless
    /// already open. Returns the opened services.
    pub(crate) async fn unseal(
        self: &Arc<Self>,
        secret: Zeroizing<String>,
    ) -> Result<Opened, WalletAdminError> {
        let mut guard = self.opened.lock().await;
        if let Some(opened) = guard.as_ref() {
            return Ok(opened.clone());
        }
        self.throttle.lock().check()?;
        let gate = self.clone();
        let opened = tokio::task::spawn_blocking(move || gate.unseal_blocking(&secret))
            .await
            .map_err(|error| WalletAdminError::Internal(error.to_string()))?;
        match &opened {
            Ok(_) => self.throttle.lock().record_success(),
            Err(WalletAdminError::WrongPassword) => {
                self.throttle.lock().record_failure();
                tracing::warn!("wallet unseal failed: wrong password");
            }
            Err(_) => {}
        }
        let opened = opened?;
        // Serve the unsealed API before this request is answered, so a
        // request that follows the response never sees the sealed router.
        if let Some(install) = self.installer.get() {
            install(&opened);
        }
        *guard = Some(opened.clone());
        let _ = self.unsealed.send(opened.clone());
        tracing::info!("wallet database unsealed");
        Ok(opened)
    }

    fn unseal_blocking(&self, secret: &str) -> Result<Opened, WalletAdminError> {
        let internal = |error: DaemonError| WalletAdminError::Internal(error.to_string());
        let config = &self.context.config;
        let key = match config.mode {
            WalletMode::WatchOnly => watch_data_key(&config.data_dir, secret)?,
            WalletMode::Seed => {
                let dir = secret_dir(config);
                let map = |error: WalletError| match error {
                    WalletError::Decryption => WalletAdminError::WrongPassword,
                    WalletError::WalletUninitialized => WalletAdminError::Uninitialized,
                    other => WalletAdminError::Internal(other.to_string()),
                };
                match SecretStorage::open_data_key(&dir, secret).map_err(map)? {
                    Some(key) => DataKey::from_bytes(*key),
                    None => {
                        // First unseal of a wallet created before database
                        // encryption: seal a key first, so a crash can leave
                        // a cleartext database but never an unreadable one.
                        let key = DataKey::generate();
                        SecretStorage::install_data_key(&dir, secret, key.expose()).map_err(map)?;
                        key
                    }
                }
            }
        };
        open(&self.context, &key, false).map_err(internal)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SecretBody {
    pass: String,
}

/// `{initialized, locked, sealed}` while sealed.
#[derive(Serialize)]
struct SealedStatus {
    initialized: bool,
    locked: bool,
    sealed: bool,
}

fn no_store(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn native_error(error: &WalletAdminError) -> Response {
    let mapped = WalletErrorSurface::NativeV1.map(error);
    let status = StatusCode::from_u16(mapped.status).expect("protocol status is valid");
    let detail = (!status.is_server_error())
        .then_some(mapped.detail)
        .flatten();
    no_store(
        (
            status,
            Json(serde_json::json!({"reason": mapped.reason, "detail": detail})),
        )
            .into_response(),
    )
}

fn scala_error(error: &WalletAdminError) -> Response {
    let mapped = WalletErrorSurface::Scala.map(error);
    let status = StatusCode::from_u16(mapped.status).expect("protocol status is valid");
    let detail = (!status.is_server_error()).then(|| error.to_string());
    no_store(
        (
            status,
            Json(serde_json::json!({"reason": mapped.reason, "detail": detail})),
        )
            .into_response(),
    )
}

fn sealed_response() -> Response {
    no_store(
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"reason": "wallet_sealed", "detail": "unseal or unlock the wallet first"})),
        )
            .into_response(),
    )
}

fn parse_secret(body: &[u8]) -> Result<Zeroizing<String>, Response> {
    let body = Zeroizing::new(body.to_vec());
    serde_json::from_slice::<SecretBody>(&body)
        .map(|body| Zeroizing::new(body.pass))
        .map_err(|_| {
            no_store(
                (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"reason": "bad_request", "detail": "expected {\"pass\": string}"})),
                )
                    .into_response(),
            )
        })
}

async fn status(State(gate): State<Arc<Gate>>) -> Response {
    let config = &gate.context.config;
    let initialized = match config.mode {
        WalletMode::Seed => keystore_exists(config).unwrap_or(true),
        WalletMode::WatchOnly => config.data_dir.join(WATCH_KEY_FILE).exists(),
    };
    no_store(
        Json(SealedStatus {
            initialized,
            locked: true,
            sealed: true,
        })
        .into_response(),
    )
}

/// Unseal, then (seed mode) unlock the engine with the same password.
async fn unlock_with(gate: Arc<Gate>, body: axum::body::Bytes, scala: bool) -> Response {
    let render = if scala { scala_error } else { native_error };
    let secret = match parse_secret(&body) {
        Ok(secret) => secret,
        Err(response) => return response,
    };
    let opened = match gate.unseal(secret.clone()).await {
        Ok(opened) => opened,
        Err(error) => return render(&error),
    };
    if let Some(host) = opened.host {
        if let Err(error) = host.unlock(secret.to_string()).await {
            return render(&error);
        }
    }
    no_store(StatusCode::OK.into_response())
}

async fn unlock_native(State(gate): State<Arc<Gate>>, body: axum::body::Bytes) -> Response {
    unlock_with(gate, body, false).await
}

async fn unlock_scala(State(gate): State<Arc<Gate>>, body: axum::body::Bytes) -> Response {
    unlock_with(gate, body, true).await
}

/// Unseal without unlocking: sync resumes, spending stays locked.
async fn unseal(State(gate): State<Arc<Gate>>, body: axum::body::Bytes) -> Response {
    let secret = match parse_secret(&body) {
        Ok(secret) => secret,
        Err(response) => return response,
    };
    match gate.unseal(secret).await {
        Ok(_) => no_store(StatusCode::OK.into_response()),
        Err(error) => native_error(&error),
    }
}

async fn seal(State(gate): State<Arc<Gate>>) -> Response {
    tracing::info!("wallet seal requested; stopping the daemon");
    let _ = gate.seal.send(true);
    no_store(StatusCode::ACCEPTED.into_response())
}

async fn sealed_fallback() -> Response {
    sealed_response()
}

/// Authenticated routes served while sealed.
pub(crate) fn sealed_router(gate: Arc<Gate>, key: ApiKey) -> Router {
    let secret_routes = Router::new()
        .route("/api/v1/wallet/unseal", post(unseal))
        .route("/api/v1/wallet/unlock", post(unlock_native))
        .route("/wallet/unlock", post(unlock_scala))
        .layer(DefaultBodyLimit::max(MAX_SECRET_BODY));
    let api = Router::new()
        .route("/api/v1/wallet/lifecycle/status", get(status))
        .route("/api/v1/wallet/seal", post(seal))
        .merge(secret_routes)
        .fallback(sealed_fallback)
        .with_state(gate.clone())
        .layer(axum::middleware::from_fn_with_state(
            key,
            crate::lifecycle_api::authenticate,
        ));
    if gate.context.config.mode == WalletMode::Seed {
        crate::full_api::ui::router().merge(api)
    } else {
        api
    }
}

/// The authenticated `seal` route, merged into the unsealed routers.
pub(crate) fn seal_router(gate: Arc<Gate>, key: ApiKey) -> Router {
    Router::new()
        .route("/api/v1/wallet/seal", post(seal))
        .with_state(gate)
        .layer(axum::middleware::from_fn_with_state(
            key,
            crate::lifecycle_api::authenticate,
        ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn watch_key_file_is_created_once_and_needs_its_passphrase() {
        ergo_wallet::storage::use_fast_keystore_kdf_for_tests();
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(
            watch_data_key(dir.path(), "short"),
            Err(WalletAdminError::BadRequest(_))
        ));
        let key = watch_data_key(dir.path(), "a long watch passphrase").unwrap();
        assert_eq!(
            watch_data_key(dir.path(), "a long watch passphrase")
                .unwrap()
                .expose(),
            key.expose()
        );
        assert_eq!(
            watch_data_key(dir.path(), "another long passphrase").unwrap_err(),
            WalletAdminError::WrongPassword
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.path().join(WATCH_KEY_FILE))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o077, 0);
        }
    }

    #[test]
    fn cleartext_database_is_encrypted_in_place() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(WALLET_DB);
        drop(RedbWalletStore::open_standalone(&path).unwrap());
        assert!(is_cleartext(&path).unwrap());
        let key = DataKey::generate();
        drop(open_database(dir.path(), &key).unwrap());
        assert!(!is_cleartext(&path).unwrap());
        assert!(!dir.path().join(format!("{WALLET_DB}.encrypting")).exists());
        drop(open_database(dir.path(), &key).unwrap());
        assert!(matches!(
            open_database(dir.path(), &DataKey::generate()),
            Err(DaemonError::Server(message)) if message.contains("different key")
        ));
    }
}
