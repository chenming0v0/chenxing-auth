//! Issue #519: config security-posture warnings must survive the real startup
//! path. Construction returns them as data; `main` emits after tracing is live.

use std::io::{self, Write};
use std::path::PathBuf;
use std::process::Command;
use std::sync::{Arc, Mutex, OnceLock};

use chenxing_auth::config::{Config, ConfigWarning, TrustedProxies};

const HTTP_ISSUER_NEEDLE: &str = "COOKIE_SECURE=true with an HTTP APP_ISSUER";
const EMPTY_ADMIN_NEEDLE: &str = "ADMIN_TOKEN not set";
const LOOPBACK_NEEDLE: &str = "OAUTH_PROVIDER_LOOPBACK_ENABLED=true";
const NO_PROXIES_NEEDLE: &str = "TRUSTED_PROXIES not set";

const VALID_ADMIN_TOKEN: &str = "binary-startup-admin-token-012345";
const SECRET_ADMIN_TOKEN: &str = "super-secret-admin-token-LEAKME01";
const DB_SECRET: &str = "db-secret-DO-NOT-LEAK";
const REDIS_SECRET: &str = "redis-secret-DO-NOT-LEAK";
/// Standard Base64 of 32 `0x41` bytes. Searchable key material.
const ENCRYPTION_KEY: &str = "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE=";

fn production_like_config() -> Config {
    let mut config = Config::from_values_with_issuer(
        "127.0.0.1".to_owned(),
        3000,
        "https://auth.example.com".to_owned(),
        format!("postgres://db-user:{DB_SECRET}@db.example/chenxing_auth"),
        format!("redis://:{REDIS_SECRET}@redis.example/0"),
        3600,
    )
    .expect("valid production-like configuration");
    config.admin_token = SECRET_ADMIN_TOKEN.to_owned();
    config.trusted_proxies = TrustedProxies::from_ips(vec![
        "127.0.0.1".parse().expect("loopback is a valid proxy IP"),
    ]);
    config
}

fn capture_emitted_warnings(config: &Config) -> String {
    let buffer = Arc::new(Mutex::new(Vec::new()));
    let writer = buffer.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .with_target(false)
        .with_writer(move || BufferWriter(writer.clone()))
        .finish();
    tracing::subscriber::with_default(subscriber, || {
        config.emit_startup_warnings();
    });
    String::from_utf8(buffer.lock().expect("log buffer").clone()).expect("utf8 logs")
}

struct BufferWriter(Arc<Mutex<Vec<u8>>>);

impl Write for BufferWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().expect("log buffer").extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn assert_no_secrets(logs: &str) {
    for secret in [
        SECRET_ADMIN_TOKEN,
        VALID_ADMIN_TOKEN,
        DB_SECRET,
        REDIS_SECRET,
        ENCRYPTION_KEY,
        "database-password",
        "postgres://",
        "redis://",
    ] {
        assert!(
            !logs.contains(secret),
            "startup logs leaked {secret:?}: {logs}"
        );
    }
}

fn assert_only_warning(logs: &str, expected: &str) {
    assert!(logs.contains(expected), "missing {expected:?} in: {logs}");
    for needle in [
        HTTP_ISSUER_NEEDLE,
        EMPTY_ADMIN_NEEDLE,
        LOOPBACK_NEEDLE,
        NO_PROXIES_NEEDLE,
    ] {
        if needle != expected {
            assert!(
                !logs.contains(needle),
                "unexpected {needle:?} alongside {expected:?}: {logs}"
            );
        }
    }
    assert_no_secrets(logs);
}

#[test]
fn emit_http_issuer_secure_cookie_warning() {
    let mut config = production_like_config();
    config.issuer = Some(
        chenxing_auth::config::IssuerUrl::parse("http://127.0.0.1:3000")
            .expect("loopback HTTP issuer"),
    );
    assert_eq!(
        config.startup_warnings(),
        [ConfigWarning::HttpIssuerSecureCookie]
    );
    assert_only_warning(&capture_emitted_warnings(&config), HTTP_ISSUER_NEEDLE);
}

#[test]
fn emit_empty_admin_token_warning() {
    let mut config = production_like_config();
    config.admin_token.clear();
    assert_eq!(config.startup_warnings(), [ConfigWarning::EmptyAdminToken]);
    assert_only_warning(&capture_emitted_warnings(&config), EMPTY_ADMIN_NEEDLE);
}

#[test]
fn emit_oauth_loopback_warning() {
    let mut config = production_like_config();
    config.oauth_provider_loopback_enabled = true;
    assert_eq!(
        config.startup_warnings(),
        [ConfigWarning::OauthProviderLoopbackEnabled]
    );
    assert_only_warning(&capture_emitted_warnings(&config), LOOPBACK_NEEDLE);
}

#[test]
fn emit_missing_trusted_proxies_warning() {
    let mut config = production_like_config();
    config.trusted_proxies = TrustedProxies::none();
    assert_eq!(config.startup_warnings(), [ConfigWarning::NoTrustedProxies]);
    assert_only_warning(&capture_emitted_warnings(&config), NO_PROXIES_NEEDLE);
}

struct BinaryOutput {
    stdout: String,
    stderr: String,
}

fn chenxing_auth_bin() -> PathBuf {
    static BIN: OnceLock<PathBuf> = OnceLock::new();
    BIN.get_or_init(|| {
        let exe = format!("chenxing-auth{}", std::env::consts::EXE_SUFFIX);
        locate_chenxing_auth_bin(&exe).unwrap_or_else(|| build_chenxing_auth_bin(&exe))
    })
    .clone()
}

fn locate_chenxing_auth_bin(exe: &str) -> Option<PathBuf> {
    // The project test runner compiles `--test config_startup_warnings` without
    // the package binary, so `env!("CARGO_BIN_EXE_*")` is either unset or points
    // at a path that was never built. Resolve the executable at runtime.
    let mut candidates = Vec::new();
    if let Ok(path) = std::env::var("CARGO_BIN_EXE_chenxing_auth") {
        candidates.push(PathBuf::from(path));
    }
    if let Some(path) = option_env!("CARGO_BIN_EXE_chenxing_auth") {
        candidates.push(PathBuf::from(path));
    }
    let target_dir = std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target"));
    for profile in ["debug", "release"] {
        candidates.push(target_dir.join(profile).join(exe));
    }
    candidates.into_iter().find(|path| path.is_file())
}

fn build_chenxing_auth_bin(exe: &str) -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let status = Command::new(cargo)
        .args(["build", "--bin", "chenxing-auth", "--locked"])
        .current_dir(&manifest_dir)
        .status()
        .expect("spawn cargo build --bin chenxing-auth");
    assert!(
        status.success(),
        "cargo build --bin chenxing-auth failed with {status}"
    );
    locate_chenxing_auth_bin(exe)
        .unwrap_or_else(|| panic!("chenxing-auth missing after cargo build --bin chenxing-auth"))
}

fn run_binary(overrides: &[(&str, &str)]) -> BinaryOutput {
    let work = std::env::temp_dir().join(format!(
        "chenxing-auth-issue-519-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ));
    std::fs::create_dir_all(&work).expect("temp dir");

    let output = Command::new(chenxing_auth_bin())
        .arg("audit-archive")
        .current_dir(&work)
        .env_clear()
        .env(
            "DATABASE_URL",
            format!("postgres://db-user:{DB_SECRET}@127.0.0.1:1/chenxing_auth"),
        )
        .env("REDIS_URL", format!("redis://:{REDIS_SECRET}@127.0.0.1:1"))
        .env("AUTH_ENCRYPTION_KEY", ENCRYPTION_KEY)
        .env("ADMIN_TOKEN", VALID_ADMIN_TOKEN)
        .env("APP_ISSUER", "https://auth.example.com")
        .env("TRUSTED_PROXIES", "127.0.0.1")
        .env("OAUTH_PROVIDER_LOOPBACK_ENABLED", "false")
        .env("COOKIE_SECURE", "true")
        .env("AUDIT_ARCHIVE_ENABLED", "false")
        .env("RUST_LOG", "chenxing_auth=warn")
        .envs(overrides.iter().copied())
        .output()
        .expect("spawn chenxing-auth");
    let _ = std::fs::remove_dir_all(&work);

    BinaryOutput {
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

fn binary_logs(output: &BinaryOutput) -> String {
    format!("{}\n{}", output.stdout, output.stderr)
}

#[test]
fn binary_emits_http_issuer_secure_cookie_warning() {
    let logs = binary_logs(&run_binary(&[("APP_ISSUER", "http://127.0.0.1:3000")]));
    assert_only_warning(&logs, HTTP_ISSUER_NEEDLE);
}

#[test]
fn binary_emits_empty_admin_token_warning() {
    let logs = binary_logs(&run_binary(&[("ADMIN_TOKEN", "")]));
    assert_only_warning(&logs, EMPTY_ADMIN_NEEDLE);
}

#[test]
fn binary_emits_oauth_loopback_warning() {
    let logs = binary_logs(&run_binary(&[("OAUTH_PROVIDER_LOOPBACK_ENABLED", "true")]));
    assert_only_warning(&logs, LOOPBACK_NEEDLE);
}

#[test]
fn binary_emits_missing_trusted_proxies_warning() {
    let logs = binary_logs(&run_binary(&[("TRUSTED_PROXIES", "")]));
    assert_only_warning(&logs, NO_PROXIES_NEEDLE);
}

#[test]
fn binary_invalid_log_filter_is_diagnosable_without_secrets() {
    let output = run_binary(&[("RUST_LOG", "chenxing_auth=not-a-level")]);
    let logs = binary_logs(&output);
    // `main` returns `Result<_, Box<dyn Error>>`, so the process prints Debug
    // (`Error: InvalidValue("RUST_LOG")`), not ConfigError's Display text.
    assert!(
        logs.contains(r#"InvalidValue("RUST_LOG")"#)
            || logs.contains("invalid configuration value: RUST_LOG"),
        "filter failure must name RUST_LOG: {logs}"
    );
    assert!(!logs.contains(HTTP_ISSUER_NEEDLE));
    assert!(!logs.contains(EMPTY_ADMIN_NEEDLE));
    assert_no_secrets(&logs);
}

#[test]
fn binary_startup_warnings_do_not_leak_credentials() {
    let logs = binary_logs(&run_binary(&[
        ("ADMIN_TOKEN", SECRET_ADMIN_TOKEN),
        ("TRUSTED_PROXIES", ""),
    ]));
    assert!(
        logs.contains(NO_PROXIES_NEEDLE),
        "expected proxy warning: {logs}"
    );
    assert_no_secrets(&logs);
}
