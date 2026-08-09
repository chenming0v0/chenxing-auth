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
const DOCKERIGNORE: &str = include_str!("../.dockerignore");
const STATIC_FILES_MODULE: &str = include_str!("../src/api/static_files.rs");
const AUDIT_RUNTIME_MIGRATION: &str = include_str!("../migrations/0019_audit_runtime_role.sql");

/// Where both production images place the built frontend bundle.
const WEB_DIST_IMAGE_PATH: &str = "/usr/local/share/chenxing-auth/web/dist";

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
fn runtime_dockerfile_only_packages_prebuilt_artifacts() {
    for marker in [
        "COPY container-binaries/${TARGETARCH}/chenxing-auth /usr/local/bin/chenxing-auth",
        "COPY container-web-dist /usr/local/share/chenxing-auth/web/dist",
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

/// Issue #272：两条生产镜像路径都必须带上 `web/dist`，并指向同一个 `WEB_DIST_DIR`。
///
/// 二进制只在编译期内嵌 `index.html`，它引用的 JS/CSS/字体由 `ServeDir` 从磁盘读取。
/// 镜像的 WORKDIR 是可变状态目录，相对路径 `web/dist` 必然落空，所以路径必须由
/// `WEB_DIST_DIR` 显式给出，且两条路径给出同一个值——否则一条路径能用、另一条 404。
#[test]
fn both_production_images_ship_the_web_bundle_at_the_same_web_dist_dir() {
    assert!(
        WEB_DIST_IMAGE_PATH.starts_with('/'),
        "the image bundle path must be absolute: WORKDIR is the mutable state \
         directory, so a relative path would resolve outside the bundle"
    );

    let env_line = format!("WEB_DIST_DIR={WEB_DIST_IMAGE_PATH}");
    for (name, dockerfile, copy) in [
        (
            "Dockerfile",
            DOCKERFILE,
            format!("COPY --from=builder /build/web/dist {WEB_DIST_IMAGE_PATH}"),
        ),
        (
            "Dockerfile.runtime",
            RUNTIME_DOCKERFILE,
            format!("COPY container-web-dist {WEB_DIST_IMAGE_PATH}"),
        ),
    ] {
        assert!(
            dockerfile.contains(&copy),
            "{name} must ship the frontend bundle into the runtime image: {copy}"
        );
        assert!(
            dockerfile.contains(&env_line),
            "{name} must point WEB_DIST_DIR at the shipped bundle: {env_line}"
        );
        assert!(
            dockerfile.contains("WORKDIR /var/lib/chenxing-auth"),
            "{name} keeps WORKDIR on mutable state, which is why WEB_DIST_DIR is required"
        );
    }
}

/// Issue #272：`WEB_DIST_DIR` 必须是服务端读取静态资源的唯一入口，且不得为空。
///
/// 空值会让 `ServeDir` 把整个工作目录当静态根，把 `.env` 和私钥暴露成可下载文件；
/// 镜像里 WORKDIR 正是密钥目录的父级，所以这个降级在生产等于泄露。
#[test]
fn runtime_reads_the_bundle_only_through_web_dist_dir() {
    assert!(
        STATIC_FILES_MODULE.contains("env::var(\"WEB_DIST_DIR\")"),
        "the served directory must come from WEB_DIST_DIR"
    );
    assert!(
        STATIC_FILES_MODULE.contains("ServeDir::new(dist_dir)"),
        "static serving must use the resolved bundle directory"
    );
    assert!(
        STATIC_FILES_MODULE.contains(".filter(|value| !value.trim().is_empty())"),
        "an empty WEB_DIST_DIR must fall back instead of exposing the working directory"
    );

    // 单二进制约束：只有 SPA shell 内嵌，资源不内嵌，所以镜像必须带目录。
    assert_eq!(
        STATIC_FILES_MODULE
            .matches(
                "include_str!(concat!(env!(\"CARGO_MANIFEST_DIR\"), \"/web/dist/index.html\"))"
            )
            .count(),
        1,
        "only index.html may be embedded; assets must ship as files"
    );
    assert!(
        STATIC_FILES_MODULE.contains("/web/dist/index.html\"))"),
        "the embedded shell must come from the built bundle, not from generated HTML"
    );
}

/// Issue #272：从 `index.html` 的资源引用反推镜像/上下文路径设计是否成立。
///
/// 内嵌的 shell 用 `/assets/<name>-<hash>.js` 这类根绝对路径引用资源，因此
/// `WEB_DIST_DIR` 必须正好是 dist 根目录，且整棵目录都要进镜像——只拷 `assets/`
/// 会漏掉 favicon 和字体，只拷 `index.html` 则全部资源 404。
#[test]
fn embedded_index_html_asset_references_require_the_whole_bundle_root() {
    let dist = Path::new("web/dist");
    // build.rs 在产物缺失时会 panic，所以走到测试阶段它必然存在。
    let html = std::fs::read_to_string(dist.join("index.html"))
        .expect("web/dist/index.html must exist; build.rs guarantees it");

    let references = root_absolute_references(&html);
    assert!(
        references
            .iter()
            .any(|reference| reference.ends_with(".js")),
        "the built shell must reference a hashed script: {references:?}"
    );

    let mut referenced_dirs = Vec::new();
    for reference in &references {
        let relative = reference.trim_start_matches('/');
        assert!(
            dist.join(relative).is_file(),
            "index.html references {reference}, which is missing from the bundle; \
             the image must copy the whole dist root"
        );
        let dir = relative.rsplit_once('/').map_or("", |(dir, _)| dir);
        if !referenced_dirs.contains(&dir) {
            referenced_dirs.push(dir);
        }
    }

    // 根绝对引用意味着 URL 路径直接映射到 dist 根，任何前缀化的拷贝都会错位。
    assert!(
        referenced_dirs.contains(&""),
        "root-absolute references include bundle-root files (favicon等), so \
         WEB_DIST_DIR must be the dist root itself: {referenced_dirs:?}"
    );
}

/// Issue #272：CI 上下文必须把二进制编译时用的那份 `web/dist` 一起 staged。
///
/// `index.html` 里的文件名带内容哈希，一旦镜像里的产物来自另一次构建，哈希不匹配，
/// 每个资源都会 404。所以容器 Job 必须复用 `web-dist` artifact，而不是重新构建。
#[test]
fn container_job_stages_the_same_web_bundle_the_binaries_embedded() {
    for marker in [
        "needs: [web, rust-binaries]",
        "name: web-dist",
        "path: container-web-dist",
        "name: Stage container web bundle",
        "test -f container-web-dist/index.html",
        "WEB_DIST_DIR:?WEB_DIST_DIR must be set",
    ] {
        assert!(
            BUILD_WORKFLOW.contains(marker),
            "container job is missing web bundle staging marker: {marker}"
        );
    }

    // 容器 Job 不得自己跑前端构建，否则产出的哈希与二进制内嵌的不一致。
    let job_at = BUILD_WORKFLOW.find("  container:").expect("container job");
    let container_job = &BUILD_WORKFLOW[job_at..];
    assert!(
        !container_job.contains("npm ci"),
        "the container job must reuse the web-dist artifact instead of rebuilding it"
    );

    let staged_at = BUILD_WORKFLOW
        .find("name: Stage container web bundle")
        .expect("web bundle staging step");
    let smoke_at = BUILD_WORKFLOW
        .find("Smoke test final container per architecture")
        .expect("smoke test step");
    assert!(
        staged_at < smoke_at,
        "the bundle must be staged before the image is built"
    );

    // 源码镜像自己构建产物，本地陈旧的 web/dist 不能进上下文顶掉它；
    // 而 CI staged 的目录必须留在上下文里，否则 runtime 镜像拷不到。
    assert!(
        DOCKERIGNORE.lines().any(|line| line.trim() == "web/dist"),
        "a local web/dist must stay out of the build context"
    );
    assert!(
        !DOCKERIGNORE
            .lines()
            .any(|line| line.trim().starts_with("container-web-dist")),
        "the CI-staged bundle must remain in the build context"
    );
}

/// 取出 HTML 里 `src="/..."` / `href="/..."` 形式的根绝对引用。
///
/// 只认根绝对路径：相对引用和外部 URL 不受 `WEB_DIST_DIR` 布局影响。
fn root_absolute_references(html: &str) -> Vec<String> {
    let mut references = Vec::new();
    for attribute in ["src=\"", "href=\""] {
        let mut rest = html;
        while let Some(start) = rest.find(attribute) {
            rest = &rest[start + attribute.len()..];
            let Some(end) = rest.find('"') else { break };
            let value = &rest[..end];
            rest = &rest[end + 1..];
            if value.starts_with('/') && !value.starts_with("//") {
                references.push(value.to_owned());
            }
        }
    }
    references
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
    assert!(DB_MODULE.contains("external provider requires email_verified claim"));
    assert!(DB_MODULE.contains("0021_oauth_provider_require_email_verified_claim.sql"));
    assert!(DB_MODULE.contains("session outbox retention and dead letters"));
    assert!(DB_MODULE.contains("0022_session_outbox_retention.sql"));
    assert!(DB_MODULE.contains("consent state version for cache staleness detection"));
    assert!(DB_MODULE.contains("0023_consent_state_version.sql"));
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
            std::ffi::OsString::from("0021_oauth_provider_require_email_verified_claim.sql"),
            std::ffi::OsString::from("0022_session_outbox_retention.sql"),
            std::ffi::OsString::from("0023_consent_state_version.sql"),
        ]
    );
}

/// Issue #275：保留窗口迁移必须留下可执行的回滚说明。
///
/// 这条迁移引入了一个不可逆的语义：dead-letter 行退出重试。回滚会让它们重新被
/// 领取，而 `dead_lettered_at` 一旦随列一起被丢弃就再也分不清"放弃了"和"还会重试"。
/// 断言写在文本上，因为要守住的是"迁移文件自带回滚剧本"这个约定，不需要数据库。
#[test]
fn session_outbox_retention_migration_documents_its_rollback() {
    let migration = include_str!("../migrations/0022_session_outbox_retention.sql");
    for marker in [
        "Rollback note",
        "DROP INDEX session_outbox_processed_cleanup_idx;",
        "DROP INDEX session_outbox_dead_letter_idx;",
        "DROP CONSTRAINT session_outbox_state_check,",
        "DROP COLUMN dead_lettered_at;",
        "CREATE INDEX session_outbox_pending_idx",
    ] {
        assert!(
            migration.contains(marker),
            "retention migration is missing rollback marker: {marker}"
        );
    }
    assert!(
        !migration.contains("DROP TABLE"),
        "retention migration must not drop data-bearing tables"
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
