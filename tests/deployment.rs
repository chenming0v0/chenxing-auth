use std::path::Path;

use sha2::{Digest, Sha384};

const BUILD_WORKFLOW: &str = include_str!("../.github/workflows/build.yml");
const INSTALL_SCRIPT: &str = include_str!("../deploy/install.sh");
const PRODUCTION_COMPOSE: &str = include_str!("../docker-compose.prod.yml");
const DB_MODULE: &str = include_str!("../src/db.rs");
const DB_POOL_MODULE: &str = include_str!("../src/db_pool.rs");
const ENV_EXAMPLE: &str = include_str!("../.env.example");
const DOCKERFILE: &str = include_str!("../Dockerfile");
const RUNTIME_DOCKERFILE: &str = include_str!("../Dockerfile.runtime");
const AUDIT_RUNTIME_MIGRATION: &str = include_str!("../migrations/0019_audit_runtime_role.sql");

#[test]
fn release_workflow_publishes_versioned_archives_and_checksums() {
    for marker in [
        "actions/download-artifact@v4",
        "softprops/action-gh-release@v2",
        "SHA256SUMS",
        "(cd dist && sha256sum * > SHA256SUMS)",
        "Verify downloaded release assets",
        "gh release download",
        "sha256sum -c SHA256SUMS",
        "if: startsWith(github.ref, 'refs/tags/v')",
    ] {
        assert!(
            BUILD_WORKFLOW.contains(marker),
            "release workflow is missing marker: {marker}"
        );
    }
}

#[test]
fn release_workflow_keeps_all_supported_targets() {
    for target in [
        "x86_64-unknown-linux-gnu",
        "aarch64-unknown-linux-gnu",
        "x86_64-pc-windows-gnu",
        "x86_64-pc-windows-msvc",
        "x86_64-apple-darwin",
        "aarch64-apple-darwin",
    ] {
        assert!(
            BUILD_WORKFLOW.contains(target),
            "target is missing: {target}"
        );
    }
}

#[test]
fn release_workflow_builds_web_once_and_reuses_it() {
    for marker in [
        "name: Build embedded web",
        "name: web-dist",
        "needs: web",
        "path: web/dist",
        "CHENXING_USE_PREBUILT_WEB",
        "Accept prebuilt embedded web",
    ] {
        assert!(
            BUILD_WORKFLOW.contains(marker),
            "release workflow is missing web reuse marker: {marker}"
        );
    }

    let web_build_steps = BUILD_WORKFLOW
        .matches("npm ci --prefix web && npm run build --prefix web")
        .count();
    assert_eq!(
        web_build_steps, 1,
        "embedded web must be built exactly once in the release workflow"
    );
}

#[test]
fn release_workflow_builds_linux_arm_natively_and_packages_containers() {
    for marker in [
        "ubuntu-24.04-arm",
        "rust:1.94-bookworm",
        "Dockerfile.runtime",
        "container-binaries/amd64",
        "container-binaries/arm64",
        "binary-x86_64-unknown-linux-gnu",
        "binary-aarch64-unknown-linux-gnu",
        "platforms: linux/amd64,linux/arm64",
        "ldd -r",
        "Smoke test final container per architecture",
    ] {
        assert!(
            BUILD_WORKFLOW.contains(marker),
            "release workflow is missing container packaging marker: {marker}"
        );
    }

    assert!(
        !BUILD_WORKFLOW.contains("builder: cross"),
        "Linux arm64 must build natively instead of through cross/QEMU cargo"
    );
    assert!(
        BUILD_WORKFLOW.contains("file: Dockerfile.runtime"),
        "container job must package with Dockerfile.runtime"
    );
}

#[test]
fn runtime_dockerfile_only_packages_prebuilt_binaries() {
    for marker in [
        "COPY container-binaries/${TARGETARCH}/chenxing-auth /usr/local/bin/chenxing-auth",
        "ARG TARGETARCH",
        "ENTRYPOINT [\"/usr/local/bin/chenxing-auth\"]",
    ] {
        assert!(
            RUNTIME_DOCKERFILE.contains(marker),
            "runtime Dockerfile is missing marker: {marker}"
        );
    }
    assert!(
        !RUNTIME_DOCKERFILE.contains("cargo build"),
        "runtime Dockerfile must not compile Rust"
    );
    assert!(
        !RUNTIME_DOCKERFILE.contains("npm "),
        "runtime Dockerfile must not build the frontend"
    );
}

#[test]
fn source_dockerfile_still_supports_local_compose_builds() {
    for marker in [
        "FROM node:22-bookworm-slim AS web-builder",
        "FROM rust:1.94-bookworm AS builder",
        "COPY build.rs build_logic.rs ./",
        "RUN cargo build --release --locked",
        "COPY --from=builder /build/target/release/chenxing-auth /usr/local/bin/chenxing-auth",
    ] {
        assert!(
            DOCKERFILE.contains(marker),
            "source Dockerfile is missing marker: {marker}"
        );
    }
}

#[test]
fn installer_validates_compose_and_reports_application_logs() {
    for marker in [
        "docker compose --env-file .env -f docker-compose.prod.yml config",
        "docker compose --env-file .env -f docker-compose.prod.yml logs app",
        "deploy/repair-v106-checksum.sql",
        "POSTGRES_RUNTIME_USER",
        "POSTGRES_RUNTIME_PASSWORD",
        "MIGRATION_DATABASE_URL",
        "CHENXING_ISSUER",
        "APP_PORT",
    ] {
        assert!(
            INSTALL_SCRIPT.contains(marker),
            "installer is missing marker: {marker}"
        );
    }
}

#[test]
fn production_probes_use_readiness_and_keep_liveness_separate() {
    assert!(PRODUCTION_COMPOSE.contains("/health/ready"));
    assert!(!PRODUCTION_COMPOSE.contains("http://127.0.0.1:3000/health\"]"));
    assert!(INSTALL_SCRIPT.contains("/health/ready"));
    assert!(!INSTALL_SCRIPT.contains("/health/live"));
}

#[test]
fn installer_rejects_implicit_localhost_and_checks_discovery_contract() {
    for marker in [
        "CHENXING_ISSUER is required",
        "CHENXING_ALLOW_LOOPBACK_HTTP",
        "EXPECTED_COOKIE_SECURE",
        "OpenID discovery does not match APP_ISSUER",
        ".well-known/openid-configuration",
    ] {
        assert!(
            INSTALL_SCRIPT.contains(marker),
            "installer is missing issuer safety marker: {marker}"
        );
    }
    assert!(!INSTALL_SCRIPT.contains("http://localhost:3000"));
    assert!(
        !INSTALL_SCRIPT
            .lines()
            .any(|line| line == "COOKIE_SECURE=true")
    );
}

#[test]
fn deployment_files_are_present_at_repository_root() {
    assert!(Path::new(".github/workflows/build.yml").is_file());
    assert!(Path::new("deploy/install.sh").is_file());
    assert!(Path::new("deploy/repair-v106-checksum.sql").is_file());
    assert!(Path::new("docker-compose.prod.yml").is_file());
    assert!(Path::new("Dockerfile").is_file());
    assert!(Path::new("Dockerfile.runtime").is_file());
}

#[test]
fn database_uses_explicit_unified_baseline_migrations() {
    assert!(DB_MODULE.contains("unified identity baseline"));
    assert!(DB_MODULE.contains("plans and entitlements"));
    assert!(DB_MODULE.contains("session outbox consistency"));
    assert!(DB_MODULE.contains("session outbox deleted target cleanup"));
    assert!(DB_MODULE.contains("session outbox event user retention"));
    assert!(DB_MODULE.contains("session revocation epochs"));
    assert!(DB_MODULE.contains("include_str!(\"../migrations/0001_initial.sql\")"));
    assert!(DB_MODULE.contains("include_str!(\"../migrations/0002_plans.sql\")"));
    assert!(DB_MODULE.contains("0003_session_outbox.sql"));
    assert!(DB_MODULE.contains("0004_relax_deleted_session_outbox_target.sql"));
    assert!(DB_MODULE.contains("0005_session_outbox_event_user.sql"));
    assert!(DB_MODULE.contains("0006_session_epochs.sql"));
    assert!(DB_MODULE.contains("plan default invariant"));
    assert!(DB_MODULE.contains("0007_plan_default_invariant.sql"));
    assert!(DB_MODULE.contains("admin query indexes"));
    assert!(DB_MODULE.contains("0008_admin_query_indexes.sql"));
    assert!(DB_MODULE.contains("system settings seeds"));
    assert!(DB_MODULE.contains("0009_system_settings.sql"));
    assert!(DB_MODULE.contains("durable consent revocation"));
    assert!(DB_MODULE.contains("0010_consent_revoked_at.sql"));
    assert!(DB_MODULE.contains("external provider PKCE toggle"));
    assert!(DB_MODULE.contains("0011_oauth_provider_pkce.sql"));
    assert!(DB_MODULE.contains("restore basic plan seed"));
    assert!(DB_MODULE.contains("0012_restore_basic_plan.sql"));
    assert!(DB_MODULE.contains("audit append-only retention"));
    assert!(DB_MODULE.contains("0013_audit_append_only_retention.sql"));
    assert!(DB_MODULE.contains("session idle policy"));
    assert!(DB_MODULE.contains("0014_session_idle_policy.sql"));
    assert!(DB_MODULE.contains("admin search indexes"));
    assert!(DB_MODULE.contains("0015_admin_search_indexes.sql"));
    assert!(DB_MODULE.contains("client secret rotation compare-and-swap version"));
    assert!(DB_MODULE.contains("0016_client_secret_rotation_version.sql"));
    assert!(DB_MODULE.contains("relax plan default policy"));
    assert!(DB_MODULE.contains("0017_relax_plan_default_policy.sql"));
    assert!(DB_MODULE.contains("seed security limits"));
    assert!(DB_MODULE.contains("0018_seed_security_limits.sql"));
    assert!(DB_MODULE.contains("audit runtime role separation"));
    assert!(DB_MODULE.contains("0019_audit_runtime_role.sql"));
    let mut migrations = std::fs::read_dir("migrations")
        .expect("migrations directory")
        .filter_map(Result::ok)
        .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "sql"))
        .map(|entry| entry.file_name())
        .collect::<Vec<_>>();
    migrations.sort();
    assert_eq!(
        migrations,
        vec![
            std::ffi::OsString::from("0001_initial.sql"),
            std::ffi::OsString::from("0002_plans.sql"),
            std::ffi::OsString::from("0003_session_outbox.sql"),
            std::ffi::OsString::from("0004_relax_deleted_session_outbox_target.sql"),
            std::ffi::OsString::from("0005_session_outbox_event_user.sql"),
            std::ffi::OsString::from("0006_session_epochs.sql"),
            std::ffi::OsString::from("0007_plan_default_invariant.sql"),
            std::ffi::OsString::from("0008_admin_query_indexes.sql"),
            std::ffi::OsString::from("0009_system_settings.sql"),
            std::ffi::OsString::from("0010_consent_revoked_at.sql"),
            std::ffi::OsString::from("0011_oauth_provider_pkce.sql"),
            std::ffi::OsString::from("0012_restore_basic_plan.sql"),
            std::ffi::OsString::from("0013_audit_append_only_retention.sql"),
            std::ffi::OsString::from("0014_session_idle_policy.sql"),
            std::ffi::OsString::from("0015_admin_search_indexes.sql"),
            std::ffi::OsString::from("0016_client_secret_rotation_version.sql"),
            std::ffi::OsString::from("0017_relax_plan_default_policy.sql"),
            std::ffi::OsString::from("0018_seed_security_limits.sql"),
            std::ffi::OsString::from("0019_audit_runtime_role.sql"),
            std::ffi::OsString::from("0020_user_avatar.sql"),
        ]
    );
}

#[test]
fn released_migration_bytes_are_immutable() {
    let cases = [
        (
            "0002_plans.sql",
            include_str!("../migrations/0002_plans.sql"),
            "714a0ae3cfa29909ebe32dde11396f378bf7ad546adc2d4f19e2aec23e7040fe6ab9ac0aa50df2e66ddb9a633333cc8c",
        ),
        (
            "0007_plan_default_invariant.sql",
            include_str!("../migrations/0007_plan_default_invariant.sql"),
            "f29a20be2d62a3d13429d4ed1ba461b0ecfa7699a5118cc8be80bed57b4de4701434f661d20ed5388dad203e69a15cb8",
        ),
        (
            "0009_system_settings.sql",
            include_str!("../migrations/0009_system_settings.sql"),
            "6092ab9b2112079914a64f3e3951cd31230ff5f53a2b414169e2ca0e18ed36bf81a433f8a019e176116fdfde3b56d4c4",
        ),
    ];

    for (name, sql, expected) in cases {
        let normalized = sql.replace("\r\n", "\n");
        let actual = Sha384::digest(normalized.as_bytes());
        assert_eq!(
            hex(&actual),
            expected,
            "published migration {name} must remain byte-identical"
        );
    }
}

#[test]
fn migration_checksum_manifest_lists_every_sql_file() {
    let manifest = include_str!("../migrations/checksums.sha256");
    let listed = manifest
        .lines()
        .filter_map(|line| line.split_whitespace().nth(1))
        .collect::<Vec<_>>();
    let mut on_disk = std::fs::read_dir("migrations")
        .expect("migrations directory")
        .filter_map(Result::ok)
        .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "sql"))
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    on_disk.sort();
    let mut listed = listed.into_iter().map(str::to_owned).collect::<Vec<_>>();
    listed.sort();
    assert_eq!(
        on_disk, listed,
        "checksum manifest must list every migration"
    );
}

#[test]
fn audit_runtime_role_migration_enforces_least_privilege() {
    for marker in [
        "chenxing_runtime",
        "GRANT USAGE ON SCHEMA",
        "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES",
        "REVOKE UPDATE, DELETE, TRUNCATE ON",
        "SECURITY DEFINER",
        "SET search_path = pg_catalog",
        "REVOKE ALL ON FUNCTION",
    ] {
        assert!(
            AUDIT_RUNTIME_MIGRATION.contains(marker),
            "audit runtime migration is missing marker: {marker}"
        );
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn application_startup_does_not_mutate_schema_outside_migrations() {
    let main = include_str!("../src/main.rs");
    assert!(main.contains("\"migrate\""));
    assert!(!main.contains("db::migrate(&state.database)"));
    assert!(!main.contains("CREATE TABLE"));
    assert!(!main.contains("ALTER TABLE"));
}

/// Issue #267：请求路径必须带服务端语句上限，维护路径必须不带。
///
/// 断言写在源码文本上，因为这个不变量的代价在生产才显现：只有真实 PostgreSQL 能
/// 观察到 `statement_timeout` 生效，而这里要守住的是"谁走哪个池"这个结构决定，
/// 不需要数据库就能验证，也不会被集成测试环境缺失掩盖。
#[test]
fn request_path_pool_enforces_statement_timeout_and_maintenance_pool_does_not() {
    assert!(
        DB_POOL_MODULE.contains("DB_STATEMENT_TIMEOUT_MS"),
        "statement timeout must be configurable"
    );
    assert!(
        DB_MODULE.contains("set_config('statement_timeout', $1, false)"),
        "statement timeout must be applied per connection as a bound parameter"
    );
    assert!(
        DB_MODULE.contains("PoolRole::Maintenance => None"),
        "the maintenance pool must not carry a statement timeout"
    );

    // 迁移与归档命令必须显式走维护池，否则长任务会被请求路径的上限截断。
    let main = include_str!("../src/main.rs");
    assert!(!main.contains("db::connect_with_url("));
    assert_eq!(
        main.matches("db::connect_maintenance(").count(),
        2,
        "both `migrate` and `audit-archive` must use the maintenance pool"
    );

    assert!(
        ENV_EXAMPLE.contains("DB_STATEMENT_TIMEOUT_MS"),
        "the tunable must be documented in .env.example"
    );
}

#[test]
fn installer_runs_migrations_before_starting_the_application() {
    let migrate =
        "docker compose --env-file .env -f docker-compose.prod.yml run --rm --build app migrate";
    let start = "docker compose --env-file .env -f docker-compose.prod.yml up -d --build app";
    let migrate_at = INSTALL_SCRIPT
        .find(migrate)
        .expect("installer must run the explicit migration command");
    let start_at = INSTALL_SCRIPT
        .find(start)
        .expect("installer must start the app explicitly");
    assert!(migrate_at < start_at, "migration must precede app startup");
}
