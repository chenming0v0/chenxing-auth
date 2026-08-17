use std::path::Path;

const BUILD_WORKFLOW: &str = include_str!("../.github/workflows/build.yml");
const CI_WORKFLOW: &str = include_str!("../.github/workflows/ci.yml");
const INSTALL_SCRIPT: &str = include_str!("../deploy/install.sh");
const REMOTE_INSTALL_SCRIPT: &str = include_str!("../install.sh");
const PRODUCTION_COMPOSE: &str = include_str!("../docker-compose.prod.yml");
const REDIS_CRASH_RECOVERY_SCRIPT: &str = include_str!("../test_sh/redis_crash_recovery.sh");
const TEST_RUNNER_CONTRACT_SCRIPT: &str = include_str!("../test_sh/test_runner_contract.sh");
const REDIS_DURABILITY_DOC: &str = include_str!("../docs/redis-durability.md");
const DB_MODULE: &str = include_str!("../src/db/mod.rs");
const DB_POOL_MODULE: &str = include_str!("../src/db/pool.rs");
const DB_AUDIT_BOUNDARY_MODULE: &str = include_str!("../src/db/audit_boundary.rs");
const DB_ROLES_MODULE: &str = include_str!("../src/db/roles.rs");
const DB_MIGRATE_MODULE: &str = include_str!("../src/db/migrate.rs");
const DB_MIGRATION_COMPAT_MODULE: &str = include_str!("../src/db/migration_compat.rs");
const DB_MIGRATION_PREFLIGHT_MODULE: &str = include_str!("../src/db/migration_preflight.rs");
const ENV_EXAMPLE: &str = include_str!("../.env.example");
const DOCKERFILE: &str = include_str!("../Dockerfile");
const RUNTIME_DOCKERFILE: &str = include_str!("../Dockerfile.runtime");
const DOCKERIGNORE: &str = include_str!("../.dockerignore");
const STATIC_FILES_MODULE: &str = include_str!("../src/api/static_files.rs");
const HEALTH_MODULE: &str = include_str!("../src/api/health.rs");
const OAUTH_RESPONSE_MODULE: &str = include_str!("../src/oauth/response.rs");
const OAUTH_TOKEN_SUPPORT_MODULE: &str = include_str!("../src/oauth/token_use_case_support.rs");
const OAUTH_ERROR_MODULE: &str = include_str!("../src/error.rs");
const WEB_DIST_MODULE: &str = include_str!("../src/web_dist.rs");
const CONFIG_CONSTRUCTION_MODULE: &str = include_str!("../src/config/construction.rs");
const STATE_MODULE: &str = include_str!("../src/state.rs");
const DATABASE_BASELINE: &str = include_str!("../migrations/0001_initial.sql");
const PUBLISHED_MIGRATION_CHECKSUMS: &str =
    include_str!("../migrations/published-checksums.sha256");

/// Where both production images place the built frontend bundle.
const WEB_DIST_IMAGE_PATH: &str = "/usr/local/share/chenxing-auth/web/dist";

fn migration_history_sql() -> String {
    let mut migrations = std::fs::read_dir("migrations")
        .expect("migrations directory")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|extension| extension == "sql"))
        .collect::<Vec<_>>();
    migrations.sort();
    migrations
        .into_iter()
        .map(|path| std::fs::read_to_string(path).expect("read migration SQL"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn heredoc_body_after<'a>(script: &'a str, marker: &str) -> &'a str {
    let (_, body) = script
        .split_once(marker)
        .unwrap_or_else(|| panic!("installer is missing heredoc marker: {marker}"));
    body.split_once("\nEOF")
        .map(|(body, _)| body)
        .expect("generated .env heredoc must terminate with EOF")
}

fn shell_function_body<'a>(script: &'a str, name: &str) -> &'a str {
    let declaration = format!("{name}() {{\n");
    let (_, body) = script
        .split_once(&declaration)
        .unwrap_or_else(|| panic!("installer is missing function: {name}"));
    body.split_once("\n}\n")
        .map(|(body, _)| body)
        .unwrap_or_else(|| panic!("installer function is not terminated: {name}"))
}

fn workflow_job<'a>(workflow: &'a str, name: &str) -> &'a str {
    let marker = format!("\n  {name}:\n");
    let start = workflow
        .find(&marker)
        .unwrap_or_else(|| panic!("workflow is missing job: {name}"))
        + 1;
    let rest = &workflow[start..];
    let end = rest
        .match_indices("\n  ")
        .find_map(|(offset, _)| {
            let candidate = &rest[offset + 1..];
            let line = candidate.lines().next()?;
            (!line.starts_with("    ") && line.ends_with(':')).then_some(offset)
        })
        .unwrap_or(rest.len());
    &rest[..end]
}

fn workflow_top_level_permissions(workflow: &str) -> &str {
    workflow
        .split_once("\npermissions:\n")
        .and_then(|(_, rest)| rest.split_once("\njobs:\n"))
        .map(|(permissions, _)| permissions)
        .expect("workflow must declare top-level permissions before jobs")
}

#[test]
fn release_workflow_publishes_versioned_archives_and_checksums() {
    for marker in [
        "actions/download-artifact@v4",
        "softprops/action-gh-release@v2",
        "SHA256SUMS",
        "(cd dist && sha256sum * > SHA256SUMS)",
        "Verify downloaded release assets",
        "gh release download",
        "--repo \"${GITHUB_REPOSITORY}\"",
        "sha256sum -c SHA256SUMS",
        "startsWith(github.ref, 'refs/tags/v')",
        "github.event_name == 'push'",
    ] {
        assert!(
            BUILD_WORKFLOW.contains(marker),
            "release workflow is missing marker: {marker}"
        );
    }
}

#[test]
fn build_workflow_scopes_write_permissions_and_drops_checkout_credentials() {
    let defaults = workflow_top_level_permissions(BUILD_WORKFLOW);
    assert!(defaults.contains("  contents: read"));
    assert!(defaults.contains("  actions: read"));
    assert!(!defaults.contains("write"));

    let release = workflow_job(BUILD_WORKFLOW, "release");
    assert!(release.contains("permissions:\n      contents: write"));
    assert!(!release.contains("packages: write"));

    let container = workflow_job(BUILD_WORKFLOW, "container");
    assert!(container.contains("permissions:\n      contents: read\n      packages: write"));
    assert!(!container.contains("contents: write"));

    for name in ["verify-provenance", "web", "rust-binaries"] {
        let job = workflow_job(BUILD_WORKFLOW, name);
        assert!(
            !job.contains("contents: write") && !job.contains("packages: write"),
            "ordinary build job {name} must not receive write permissions"
        );
    }

    for name in ["web", "rust-binaries", "container"] {
        let job = workflow_job(BUILD_WORKFLOW, name);
        assert!(job.contains("actions/checkout@v4"));
        assert!(
            job.contains("persist-credentials: false"),
            "repository code checkout in {name} must not persist the job token"
        );
    }
}

#[test]
fn deployment_runtime_and_migration_credentials_are_separated() {
    let app_start = PRODUCTION_COMPOSE
        .find("\n  app:")
        .expect("production compose must define app");
    let app_end = PRODUCTION_COMPOSE
        .find("\n  migrate:")
        .expect("production compose must define migrate after app");
    let app = &PRODUCTION_COMPOSE[app_start..app_end];
    assert!(
        !app.contains("env_file:"),
        "app must use an explicit runtime allowlist"
    );
    for secret in [
        "MIGRATION_DATABASE_URL",
        "POSTGRES_USER",
        "POSTGRES_PASSWORD",
    ] {
        assert!(
            !app.contains(secret),
            "app must not receive owner credential {secret}"
        );
    }
    let migrate = PRODUCTION_COMPOSE
        .split_once("\n  migrate:")
        .map(|(_, rest)| rest)
        .expect("production compose must define a migrate service");
    for marker in [
        "profiles:",
        "command: [\"migrate\"]",
        "MIGRATION_DATABASE_URL:",
        "DATABASE_URL:",
    ] {
        assert!(
            migrate.contains(marker),
            "migrate service is missing {marker}"
        );
    }
    assert!(INSTALL_SCRIPT.contains("run --rm --build migrate"));
    assert!(REMOTE_INSTALL_SCRIPT.contains("run --rm migrate"));
    for script in [INSTALL_SCRIPT, REMOTE_INSTALL_SCRIPT] {
        assert!(!script.contains("run --rm app migrate"));
    }
    assert!(REMOTE_INSTALL_SCRIPT.contains("  migrate:\n"));
    let generated = REMOTE_INSTALL_SCRIPT
        .split_once("services:\n")
        .map(|(_, body)| body)
        .expect("remote installer must generate a compose document");
    let generated_app_start = generated
        .find("  app:")
        .expect("generated compose must define app");
    let generated_app_end = generated
        .find("\n  migrate:")
        .expect("generated compose must define migrate after app");
    let generated_app = &generated[generated_app_start..generated_app_end];
    assert!(!generated_app.contains("env_file:"));
    assert!(!generated_app.contains("MIGRATION_DATABASE_URL:"));
}

#[test]
fn installers_harden_env_files_before_any_legacy_read_or_write() {
    let deploy_security = INSTALL_SCRIPT
        .find("if [[ -e .env || -L .env ]]")
        .expect("source installer must classify every existing .env path");
    let deploy_read = INSTALL_SCRIPT
        .find("APP_ISSUER=\"$(read_env_value APP_ISSUER)\"")
        .expect("source installer must read legacy APP_ISSUER");
    assert!(deploy_security < deploy_read);
    for marker in [
        "[[ -L .env ]]",
        "[[ ! -f .env ]]",
        "chmod 600 -- .env",
        "chmod 600 -- .env",
    ] {
        assert!(
            INSTALL_SCRIPT.contains(marker),
            "source installer missing {marker}"
        );
    }

    let remote_security = REMOTE_INSTALL_SCRIPT
        .find("if [[ -e \"$ENV_FILE\" || -L \"$ENV_FILE\" ]]")
        .expect("remote installer must classify every existing .env path");
    let remote_read = REMOTE_INSTALL_SCRIPT
        .find("APP_ISSUER=\"$(read_env_value APP_ISSUER)\"")
        .expect("remote installer must read legacy APP_ISSUER");
    assert!(remote_security < remote_read);
    for marker in ["[[ -L \"$ENV_FILE\" ]]", "chmod 600 -- \"$ENV_FILE\""] {
        assert!(
            REMOTE_INSTALL_SCRIPT.contains(marker),
            "remote installer missing {marker}"
        );
    }
}

#[test]
fn deployment_project_names_are_stable_and_legacy_resolution_fails_closed() {
    assert!(INSTALL_SCRIPT.contains("COMPOSE_PROJECT_NAME"));
    assert!(INSTALL_SCRIPT.contains("resolve_legacy_project"));
    assert!(INSTALL_SCRIPT.contains("docker volume inspect"));
    assert!(INSTALL_SCRIPT.contains("fail closed") || INSTALL_SCRIPT.contains("无法确认"));
    assert!(
        REMOTE_INSTALL_SCRIPT.contains("append_env_default COMPOSE_PROJECT_NAME chenxing-auth")
    );
    assert!(!REMOTE_INSTALL_SCRIPT.contains("resolve_legacy_project"));
    let generated = heredoc_body_after(INSTALL_SCRIPT, "    cat > .env <<EOF\n");
    assert!(generated.contains("COMPOSE_PROJECT_NAME="));
    assert!(!INSTALL_SCRIPT.contains("append_env_default COMPOSE_PROJECT_NAME"));
    assert!(REMOTE_INSTALL_SCRIPT.contains("COMPOSE_PROJECT_NAME=chenxing-auth"));
}

#[test]
fn compose_keeps_container_listener_fixed_when_host_port_changes() {
    for compose in [PRODUCTION_COMPOSE, REMOTE_INSTALL_SCRIPT] {
        assert!(compose.contains("APP_HOST: 0.0.0.0"));
        assert!(compose.contains("APP_PORT: 3000"));
        assert!(
            compose.contains("\"${APP_PORT:-3000}:3000\"")
                || compose.contains("\"${APP_PORT}:3000\"")
        );
        assert!(!compose.contains("APP_HOST: ${APP_HOST"));
        assert!(!compose.contains("APP_PORT: ${APP_PORT"));
    }
}

#[test]
fn publish_workflow_builds_release_tags_without_waiting_for_ci() {
    assert!(BUILD_WORKFLOW.contains("actions: read"));
    assert!(BUILD_WORKFLOW.contains("manual-${{ github.sha }}"));
    assert!(!BUILD_WORKFLOW.contains("type=ref,event=branch"));
    assert!(BUILD_WORKFLOW.contains("github.event_name == 'workflow_dispatch'"));
    assert!(
        BUILD_WORKFLOW
            .contains("github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v')")
    );
    assert!(BUILD_WORKFLOW.contains("github.event.workflow_run.head_sha"));
    assert!(BUILD_WORKFLOW.contains("merge-base --is-ancestor"));
    assert!(!BUILD_WORKFLOW.contains("actions/workflows/ci.yml/runs"));
    assert!(!BUILD_WORKFLOW.contains(".workflow_runs[]"));
    assert!(BUILD_WORKFLOW.contains("github.event_name == 'workflow_run'"));
    assert!(!BUILD_WORKFLOW.contains("github.ref == 'refs/heads/dev'"));
    assert!(!BUILD_WORKFLOW.contains("github.event_name != 'workflow_run'\n"));
}

#[test]
fn native_release_archives_ship_and_verify_the_matching_web_bundle() {
    let unix_at = BUILD_WORKFLOW
        .find("- name: Package Unix binary")
        .expect("Unix packaging step");
    let windows_at = BUILD_WORKFLOW
        .find("- name: Package Windows binary")
        .expect("Windows packaging step");
    let upload_at = BUILD_WORKFLOW[windows_at..]
        .find("- uses: actions/upload-artifact@v4")
        .map(|offset| windows_at + offset)
        .expect("native archive upload step");
    let unix_step = &BUILD_WORKFLOW[unix_at..windows_at];
    let windows_step = &BUILD_WORKFLOW[windows_at..upload_at];
    for marker in [
        "cp -R web/dist \"$package_root/web/dist\"",
        "chenxing-auth web/dist",
    ] {
        assert!(
            unix_step.contains(marker),
            "Unix archive missing marker: {marker}"
        );
    }
    for marker in [
        "Copy-Item `",
        "-LiteralPath \"web/dist\"",
        "Join-Path $packageRoot \"web\"",
        "Join-Path $packageRoot \"*\"",
    ] {
        assert!(
            windows_step.contains(marker),
            "Windows archive missing marker: {marker}"
        );
    }
    for marker in [
        "Smoke test downloaded native archives",
        "verified-download/chenxing-auth-*.tar.gz",
        "verified-download/chenxing-auth-*.zip",
        "tar -xzf",
        "unzip -q",
        "web/dist/index.html",
        "release archive is missing referenced asset",
    ] {
        assert!(
            BUILD_WORKFLOW.contains(marker),
            "release smoke check missing marker: {marker}"
        );
    }
}

#[test]
fn production_redis_has_durable_credential_state_and_crash_coverage() {
    for compose in [PRODUCTION_COMPOSE, REMOTE_INSTALL_SCRIPT] {
        for marker in [
            "      - --appendonly\n      - \"yes\"",
            "      - --appendfsync\n      - always",
            "      - --no-appendfsync-on-rewrite\n      - \"no\"",
            "      - --aof-load-truncated\n      - \"no\"",
            "      - --aof-use-rdb-preamble\n      - \"yes\"",
            "      - --save\n      - \"\"",
            "      - --dir\n      - /data",
            "      - --appenddirname\n      - appendonlydir",
            "      - --appendfilename\n      - appendonly.aof",
            "- chenxing-redis:/data",
        ] {
            assert!(
                compose.contains(marker),
                "Redis config missing marker: {marker:?}"
            );
        }
        assert!(!compose.contains("everysec"));
    }
    for marker in [
        "docker kill --signal KILL",
        "GETDEL",
        "authorization-code:consumed",
        "refresh:rotation:old",
        "refresh:rotation:successor",
        "refresh:tombstone:consumed",
        "refresh:tombstone:explicit-revoke",
        "refresh:family-revoked",
        "session:revoked:projection",
        "session:revoked:epoch",
        "assert_owned_container",
        "assert_missing",
        "assert_value",
        "--network none",
        "docker volume inspect",
        "aof_last_write_status:ok",
    ] {
        assert!(
            REDIS_CRASH_RECOVERY_SCRIPT.contains(marker),
            "Redis crash/recovery script missing marker: {marker}"
        );
    }
    for marker in [
        "bash -n test_sh/redis_crash_recovery.sh",
        "bash test_sh/redis_crash_recovery.sh",
        "timeout-minutes: 5",
    ] {
        assert!(
            CI_WORKFLOW.contains(marker),
            "CI missing Redis recovery marker: {marker}"
        );
    }
    for marker in [
        "RPO 0",
        "appendfsync always",
        "授权码",
        "Consumed",
        "family revoked",
        "session:revoked:epoch",
        "陈旧 Redis 备份",
        "故障后验证",
    ] {
        assert!(
            REDIS_DURABILITY_DOC.contains(marker),
            "Redis durability docs missing marker: {marker}"
        );
    }
}

#[test]
fn signing_failures_map_to_oauth_unavailable_and_gate_readiness() {
    for (module, marker) in [
        (OAUTH_RESPONSE_MODULE, "state.keys.signing_ready()"),
        (
            OAUTH_RESPONSE_MODULE,
            "error::oauth_temporarily_unavailable()",
        ),
        (OAUTH_TOKEN_SUPPORT_MODULE, "state.keys.signing_ready()"),
        (
            OAUTH_TOKEN_SUPPORT_MODULE,
            "OAuthError::temporarily_unavailable()",
        ),
        (OAUTH_ERROR_MODULE, "\"temporarily_unavailable\""),
        (
            HEALTH_MODULE,
            "let signing_ready = state.keys.signing_ready();",
        ),
        (HEALTH_MODULE, "signing_ready,"),
        (HEALTH_MODULE, "workers.ready"),
    ] {
        assert!(
            module.contains(marker),
            "signing/readiness marker missing: {marker}"
        );
    }
}

#[test]
fn ci_validates_the_remote_installer_without_weakening_coverage() {
    for marker in [
        "bash -n install.sh",
        "bash install.sh --prepare-only",
        "chenxing-remote-install",
        "config --quiet",
        "--fail-under-lines 75",
    ] {
        assert!(
            CI_WORKFLOW.contains(marker),
            "CI workflow is missing deployment or coverage marker: {marker}"
        );
    }
}

#[test]
fn test_runner_missing_tools_fail_closed_without_running_tests() {
    for marker in [
        "PATH=\"$temp_root/empty-path\"",
        "MODE=filter",
        "NEXTEST=0",
        "assert_failed_phase \"测试\" phase_test",
        "assert_failed_phase \"覆盖检查\" phase_coverage",
        "assert_failed_phase \"依赖审计\" phase_audit",
    ] {
        assert!(
            TEST_RUNNER_CONTRACT_SCRIPT.contains(marker),
            "test runner contract missing marker: {marker}"
        );
    }
    for marker in [
        "bash -n test_sh/test_runner_contract.sh",
        "bash test_sh/test_runner_contract.sh",
    ] {
        assert!(
            CI_WORKFLOW.contains(marker),
            "CI missing test runner contract marker: {marker}"
        );
    }
}

#[test]
fn deployment_configures_redis_namespaces_without_breaking_existing_env_files() {
    let example_namespaces = ENV_EXAMPLE
        .lines()
        .filter(|line| line.starts_with("REDIS_NAMESPACE="))
        .collect::<Vec<_>>();
    assert_eq!(
        example_namespaces,
        ["REDIS_NAMESPACE="],
        ".env.example must leave the required namespace empty instead of shipping a shared value"
    );
    assert!(ENV_EXAMPLE.contains("explicit upgrade compatibility"));
    assert!(
        PRODUCTION_COMPOSE.lines().any(|line| line.trim()
            == "REDIS_NAMESPACE: ${REDIS_NAMESPACE:?set REDIS_NAMESPACE to a unique non-empty value}"),
        "production Compose must reject a missing or empty namespace"
    );
    assert!(!PRODUCTION_COMPOSE.contains("REDIS_NAMESPACE:-"));
    assert!(REMOTE_INSTALL_SCRIPT.contains("REDIS_NAMESPACE=cx-$(openssl rand -hex 16)"));
    assert!(
        REMOTE_INSTALL_SCRIPT.contains("append_env_default REDIS_NAMESPACE legacy"),
        "existing remote installs must retain legacy keys"
    );
    assert!(
        INSTALL_SCRIPT
            .contains("REDIS_NAMESPACE=\"${REDIS_NAMESPACE:-cx-$(openssl rand -hex 16)}\"")
    );
    assert!(INSTALL_SCRIPT.contains("REDIS_NAMESPACE=${REDIS_NAMESPACE}"));
    assert!(
        INSTALL_SCRIPT.contains("ensure_env_value REDIS_NAMESPACE legacy"),
        "existing source installs must retain legacy keys"
    );
    for script in [REMOTE_INSTALL_SCRIPT, INSTALL_SCRIPT] {
        assert!(!script.contains("REDIS_NAMESPACE=production"));
        assert!(!script.contains("REDIS_NAMESPACE=${REDIS_NAMESPACE:-production}"));
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
        "needs: [verify-provenance, web]",
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

/// Issue #272 / #303：`WEB_DIST_DIR` 必须是服务端读取静态资源的唯一入口，
/// 且在启动期解析完毕。
///
/// 请求期解析的后果是配置错误只能表现为 404，最坏的一种是把整个工作目录当静态根，
/// 把 `.env` 和私钥暴露成可下载文件；镜像里 WORKDIR 正是密钥目录的父级。
#[test]
fn runtime_reads_the_bundle_only_through_web_dist_dir() {
    assert!(
        CONFIG_CONSTRUCTION_MODULE.contains("env::var(WEB_DIST_DIR_ENV)"),
        "the served directory must come from WEB_DIST_DIR"
    );
    assert!(
        STATIC_FILES_MODULE.contains("ServeDir::new(root.path())"),
        "static serving must use the startup-validated bundle root"
    );
    assert!(
        !STATIC_FILES_MODULE.contains("env::var"),
        "the request path must not read environment variables"
    );

    // 单二进制约束：只有 SPA shell 内嵌，资源不内嵌，所以镜像必须带目录。
    assert_eq!(
        WEB_DIST_MODULE
            .matches(
                "include_str!(concat!(env!(\"CARGO_MANIFEST_DIR\"), \"/web/dist/index.html\"))"
            )
            .count(),
        1,
        "only index.html may be embedded; assets must ship as files"
    );
    assert!(
        WEB_DIST_MODULE.contains("/web/dist/index.html\"))"),
        "the embedded shell must come from the built bundle, not from generated HTML"
    );
    assert!(
        !STATIC_FILES_MODULE.contains("include_str!"),
        "the embedded shell must have exactly one definition, in web_dist"
    );
}

/// Issue #303：静态根在启动期 canonicalize 并 fail closed，不存在回退到工作目录。
#[test]
fn the_static_root_is_canonicalized_and_validated_at_startup() {
    for marker in [
        "fs::canonicalize(&requested)",
        "WebDistError::Empty",
        "WebDistError::NotADirectory",
        "WebDistError::ForbiddenLocation",
        "WebDistError::NotABundle",
        "fn check_location(",
        "fn check_bundle(",
    ] {
        assert!(
            WEB_DIST_MODULE.contains(marker),
            "web_dist must keep the startup validation: {marker}"
        );
    }

    // 拒绝规则：文件系统根、工作目录及其被包含关系、KEY_DIRECTORY 重叠。
    for reason in [
        "the filesystem root is never a build artifact directory",
        "it is or contains the process working directory",
        "it overlaps KEY_DIRECTORY",
    ] {
        assert!(
            WEB_DIST_MODULE.contains(reason),
            "web_dist must reject this location: {reason}"
        );
    }

    // 产物根必须自证同源：index.html 在盘上，且内嵌 shell 引用的资源都能找到。
    assert!(
        WEB_DIST_MODULE.contains("format!(\"{INDEX_FILE} is missing\")"),
        "index.html must be required on disk"
    );
    assert!(
        WEB_DIST_MODULE.contains("root_absolute_references(EMBEDDED_INDEX_HTML)"),
        "the bundle must satisfy every asset the embedded shell references"
    );

    // 启动期解析必须真的被调用，且发生在监听之前。
    assert!(
        STATE_MODULE.contains("WebDistRoot::from_settings("),
        "AppState must resolve the static root at startup"
    );
    assert!(
        STATE_MODULE.contains("WebDist(#[from] WebDistError)"),
        "an invalid static root must be a startup error, not a request-time fallback"
    );
    assert!(
        !WEB_DIST_MODULE.contains("unwrap_or_else(|| DEFAULT_WEB_DIST_DIR"),
        "an empty WEB_DIST_DIR must fail closed instead of silently falling back"
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
        "needs: [verify-provenance, web, rust-binaries]",
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
        "POSTGRES_RUNTIME_USER",
        "POSTGRES_RUNTIME_PASSWORD",
        "MIGRATION_DATABASE_URL",
        "APP_ISSUER is read only for older deployments",
        "APP_PORT",
    ] {
        assert!(
            INSTALL_SCRIPT.contains(marker),
            "installer is missing marker: {marker}"
        );
    }
}

#[test]
fn remote_installer_uses_published_images_and_keeps_download_progress_visible() {
    for marker in [
        "ghcr.io/chenming0v0/chenxing-auth:latest",
        "postgres:16-alpine",
        "redis:7-alpine",
        "docker pull \"$CHENXING_IMAGE\"",
        "docker pull \"$POSTGRES_IMAGE\"",
        "docker pull \"$REDIS_IMAGE\"",
        "compose run --rm migrate",
        "compose up -d app",
        "Owner 在管理设置中写入固定的 HTTPS Issuer",
        "PostgreSQL app_settings",
        "--prepare-only",
    ] {
        assert!(
            REMOTE_INSTALL_SCRIPT.contains(marker),
            "remote installer is missing marker: {marker}"
        );
    }
    for pull in [
        "docker pull \"$CHENXING_IMAGE\"",
        "docker pull \"$POSTGRES_IMAGE\"",
        "docker pull \"$REDIS_IMAGE\"",
    ] {
        let line = REMOTE_INSTALL_SCRIPT
            .lines()
            .find(|line| line.trim() == pull)
            .expect("visible pull command");
        assert!(!line.contains("--quiet"));
        assert!(!line.contains("/dev/null"));
    }
}

#[test]
fn remote_installer_generates_and_preserves_deployment_secrets() {
    for marker in [
        "openssl rand -base64 32",
        "openssl rand -hex 32",
        "chmod 600 -- \"$ENV_FILE\"",
        "检测到已有 .env，将保留数据库密码、Token 和加密密钥",
        "AUTH_ENCRYPTION_KEY 必须是 Base64 编码的 32 字节密钥",
    ] {
        assert!(
            REMOTE_INSTALL_SCRIPT.contains(marker),
            "remote installer is missing secret marker: {marker}"
        );
    }
}

#[test]
fn fresh_installers_do_not_write_app_issuer_but_keep_legacy_env_compatibility() {
    for (name, script, marker) in [
        ("source installer", INSTALL_SCRIPT, "    cat > .env <<EOF\n"),
        (
            "remote installer",
            REMOTE_INSTALL_SCRIPT,
            "    cat > \"$ENV_FILE\" <<EOF\n",
        ),
    ] {
        let generated_env = heredoc_body_after(script, marker);
        assert!(
            !generated_env
                .lines()
                .any(|line| line.trim_start().starts_with("APP_ISSUER=")),
            "{name} must not write APP_ISSUER into a fresh .env"
        );
        assert!(
            script.contains("APP_ISSUER=\"$(read_env_value APP_ISSUER)\""),
            "{name} must still read legacy APP_ISSUER from an existing .env"
        );
    }

    assert!(INSTALL_SCRIPT.contains("APP_ISSUER is read only for older deployments"));
    assert!(REMOTE_INSTALL_SCRIPT.contains("检测到旧环境中的 APP_ISSUER"));
}

#[test]
fn production_healthchecks_and_installers_use_readiness() {
    let readiness_healthcheck =
        "test: [\"CMD\", \"curl\", \"--fail\", \"http://127.0.0.1:3000/health/ready\"]";
    assert!(PRODUCTION_COMPOSE.contains(readiness_healthcheck));
    assert!(!PRODUCTION_COMPOSE.contains("http://127.0.0.1:3000/health\"]"));
    assert!(INSTALL_SCRIPT.contains("/health/ready"));
    assert!(REMOTE_INSTALL_SCRIPT.contains(readiness_healthcheck));
    let remote_wait = shell_function_body(REMOTE_INSTALL_SCRIPT, "wait_for_application");
    for marker in [
        "for attempt in $(seq 1 60); do",
        "curl --fail --silent --max-time 5",
        "http://127.0.0.1:3000/health/ready",
        "return 0",
        "return 1",
    ] {
        assert!(
            remote_wait.contains(marker),
            "readiness wait missing marker: {marker}"
        );
    }
    assert!(!remote_wait.contains("/health/live"));
}

#[test]
fn remote_installer_reports_full_readiness_timeout_diagnostics() {
    let diagnostics = shell_function_body(REMOTE_INSTALL_SCRIPT, "report_application_diagnostics");
    for marker in [
        "compose ps >&2 || true",
        "compose ps -q app",
        "docker inspect --format",
        ".State.Health.Status",
        "compose logs app >&2 || true",
    ] {
        assert!(
            diagnostics.contains(marker),
            "readiness diagnostics missing marker: {marker}"
        );
    }
    let (_, timeout_handler) = REMOTE_INSTALL_SCRIPT
        .split_once("if ! wait_for_application; then\n")
        .expect("remote installer must handle readiness timeout");
    let timeout_handler = timeout_handler
        .split_once("\nfi\n")
        .map(|(body, _)| body)
        .expect("readiness timeout handler must terminate");
    assert!(timeout_handler.contains("report_application_diagnostics"));
}

#[test]
fn source_installer_keeps_legacy_issuer_checks_and_documents_protected_bootstrap() {
    for marker in [
        "CHENXING_ALLOW_LOOPBACK_HTTP",
        "EXPECTED_COOKIE_SECURE",
        "APP_ISSUER=\"$(read_env_value APP_ISSUER)\"",
        "OpenID discovery does not match APP_ISSUER",
        ".well-known/openid-configuration",
        "No legacy APP_ISSUER was read",
        "protected bootstrap mode",
        "ID=1 Owner",
        "Owner settings",
        "PostgreSQL app_settings",
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
    assert!(Path::new("install.sh").is_file());
    assert!(Path::new("docker-compose.prod.yml").is_file());
    assert!(Path::new("Dockerfile").is_file());
    assert!(Path::new("Dockerfile.runtime").is_file());
}

#[test]
fn database_uses_forward_only_transactional_migration_history() {
    assert!(DB_MODULE.contains("Versions 1-27 have shipped and their SQL bytes are immutable"));
    assert!(DB_MODULE.contains("include_str!(\"../../migrations/0001_initial.sql\")"));
    assert!(DB_MODULE.contains("include_str!(\"../../migrations/0029_plan_quota_bounds.sql\")"));
    // 0030/0031（passkey state version、client operation idempotency）来自
    // #50-479 批次的合并；0032 收紧 SQLx migration ledger 的运行时权限。
    assert!(
        DB_MODULE.contains("include_str!(\"../../migrations/0030_passkey_state_version.sql\")")
    );
    assert!(
        DB_MODULE
            .contains("include_str!(\"../../migrations/0031_client_operation_idempotency.sql\")")
    );
    assert!(
        DB_MODULE.contains(
            "include_str!(\"../../migrations/0032_runtime_migration_ledger_boundary.sql\")"
        )
    );
    assert_eq!(
        DB_MODULE
            .matches("include_str!(\"../../migrations/")
            .count(),
        32
    );
    assert!(
        DB_MODULE.contains("normalize_migration_sql(sql)")
            && DB_MODULE.contains("MigrationType::Simple"),
        "the schema migrations must remain transactional"
    );

    let run_migrations = DB_MODULE
        .find("migration_compat::run(database, embedded_migrator()).await?;")
        .expect("schema migrations must run");
    let preflight = DB_MIGRATION_COMPAT_MODULE
        .find("migration_preflight::verify(&mut connection).await?;")
        .expect("pg_trgm placement must be checked inside the migration lock");
    let ensure_role = DB_MIGRATION_COMPAT_MODULE
        .find("roles::ensure_runtime_role(&mut *connection).await?;")
        .expect("runtime role must be provisioned inside the migration lock");
    let ensure_ledger = DB_MIGRATION_COMPAT_MODULE
        .find("Migrate::ensure_migrations_table(&mut *connection).await?;")
        .expect("migration ledger must be initialized after preflight");
    assert!(run_migrations > 0);
    assert!(preflight < ensure_role && ensure_role < ensure_ledger);
    for checksum in [
        "ca8607f4cd8b19d91531d9081d7951d70e266ef35c686c64bcff48e89728ea95",
        "70b7c2bd57303895720d0e13fbc56b16d43645f67363803fac73411fd8e4526f",
        "56e9d9ea680ac129115cc21ac2ff5029f9f2746683bdb9cf42ad966afb3571c4",
    ] {
        assert!(
            DB_MIGRATION_COMPAT_MODULE.contains(checksum),
            "flattened published checksum must remain explicitly recognized"
        );
    }
    assert!(DB_MIGRATION_COMPAT_MODULE.contains("verify_flattened_schema"));
    assert!(DB_MIGRATION_COMPAT_MODULE.contains("Migrate::lock"));
    assert!(DB_ROLES_MODULE.contains("CREATE ROLE chenxing_runtime LOGIN"));
    assert!(!DATABASE_BASELINE.contains("CREATE ROLE"));

    let mut migrations = std::fs::read_dir("migrations")
        .expect("migrations directory")
        .filter_map(Result::ok)
        .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "sql"))
        .map(|entry| entry.file_name())
        .collect::<Vec<_>>();
    migrations.sort();
    assert_eq!(migrations.len(), 32);
    assert_eq!(
        migrations.first().and_then(|name| name.to_str()),
        Some("0001_initial.sql")
    );
    assert_eq!(
        migrations.last().and_then(|name| name.to_str()),
        Some("0032_runtime_migration_ledger_boundary.sql")
    );
    for (index, name) in migrations.iter().enumerate() {
        let expected_prefix = format!("{:04}_", index + 1);
        assert!(
            name.to_string_lossy().starts_with(&expected_prefix),
            "migration history must be contiguous at {expected_prefix}"
        );
    }

    assert_eq!(
        DATABASE_BASELINE.matches("CREATE TABLE ").count(),
        10,
        "the published version-1 migration must remain the original ten-table schema"
    );
    for table in [
        "users",
        "oauth_clients",
        "user_consents",
        "user_sessions",
        "user_totp_factors",
        "user_passkeys",
        "oauth_providers",
        "oauth_external_identities",
        "audit_events",
        "app_settings",
    ] {
        assert!(
            DATABASE_BASELINE.contains(&format!("CREATE TABLE {table} (")),
            "baseline is missing table {table}"
        );
    }
}

#[test]
fn migration_preflight_is_inside_the_sqlx_lock_and_rejects_search_path_workarounds() {
    for marker in [
        "pg_catalog.pg_extension",
        "pg_catalog.pg_namespace",
        ".bind(PG_TRGM_EXTENSION)",
        "ALTER EXTENSION pg_trgm SET SCHEMA public",
        "Changing search_path cannot satisfy this contract",
    ] {
        assert!(
            DB_MIGRATION_PREFLIGHT_MODULE.contains(marker),
            "pg_trgm preflight is missing marker: {marker}"
        );
    }

    let lock = DB_MIGRATION_COMPAT_MODULE
        .find("Migrate::lock(&mut *connection).await?;")
        .expect("migration must acquire SQLx's advisory lock");
    let preflight = DB_MIGRATION_COMPAT_MODULE
        .find("migration_preflight::verify(&mut connection).await?;")
        .expect("migration must run the pg_trgm preflight");
    let repair = DB_MIGRATION_COMPAT_MODULE
        .find("repair_flattened_ledger(&mut connection, &migrator).await?")
        .expect("flattened ledger compatibility must remain enabled");
    let disable_nested_lock = DB_MIGRATION_COMPAT_MODULE
        .find("migrator.set_locking(false);")
        .expect("run_direct must not acquire the SQLx lock twice");
    let run = DB_MIGRATION_COMPAT_MODULE
        .find("migrator.run_direct(&mut *connection).await")
        .expect("migration must run on the preflighted connection");
    let unlock = DB_MIGRATION_COMPAT_MODULE
        .find("Migrate::unlock(&mut *connection).await")
        .expect("migration must release SQLx's advisory lock");

    assert!(lock < preflight);
    assert!(preflight < repair);
    assert!(repair < disable_nested_lock);
    assert!(disable_nested_lock < run);
    assert!(run < unlock);
    assert!(DB_MIGRATION_COMPAT_MODULE.contains("connection.close_on_drop();"));
}

#[test]
fn migration_history_declares_final_security_and_consistency_invariants() {
    let history = migration_history_sql();
    for marker in [
        "ADD COLUMN IF NOT EXISTS canonical_email TEXT",
        "ALTER COLUMN canonical_email SET NOT NULL",
        "ALTER COLUMN allow_legacy_refresh_tokens SET DEFAULT FALSE",
        "client_secret_version BIGINT NOT NULL DEFAULT 0",
        "state_version BIGINT NOT NULL DEFAULT 1",
        "CONSTRAINT oauth_providers_active_requires_email_verified_claim",
        "CONSTRAINT session_outbox_state_check",
        "WHERE processed_at IS NULL AND dead_lettered_at IS NULL",
        "CREATE TRIGGER audit_events_append_only_trigger",
        "CREATE TRIGGER audit_events_archive_append_only_trigger",
        "GRANT UPDATE ON SEQUENCE %s TO chenxing_runtime",
        "REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON TABLE %I._sqlx_migrations",
        "ALTER DEFAULT PRIVILEGES IN SCHEMA %I REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON TABLES",
    ] {
        assert!(
            history.contains(marker),
            "database migration history is missing invariant: {marker}"
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

    let published = PUBLISHED_MIGRATION_CHECKSUMS.lines().collect::<Vec<_>>();
    let current = manifest.lines().collect::<Vec<_>>();
    assert_eq!(published.len(), 27);
    assert_eq!(published, current[..published.len()]);
    assert!(published.last().is_some_and(|line| {
        line.ends_with("  0027_repair_canonical_email_constraint_scope.sql")
    }));
    for marker in [
        "sha256sum -c published-checksums.sha256",
        "published_count=\"$(wc -l < published-checksums.sha256)\"",
        "head -n \"$published_count\" checksums.sha256",
    ] {
        assert!(
            CI_WORKFLOW.contains(marker),
            "CI must pin the published migration ledger: {marker}"
        );
    }
}

#[test]
fn database_baseline_enforces_runtime_role_least_privilege() {
    let history = migration_history_sql();
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
            history.contains(marker),
            "database migration history is missing runtime privilege marker: {marker}"
        );
    }
}

/// Issue #281：基线的 REVOKE 只在"运行时角色 ≠ 表 owner"时才是边界。
///
/// 断言写在源码文本上，因为这里要守住的是"迁移命令必须实测权限、不能只相信
/// 迁移文件"这个结构决定。真实权限行为由 `database_schema` 的集成用例覆盖。
#[test]
fn migrate_command_verifies_the_audit_boundary_instead_of_trusting_the_migration() {
    for marker in [
        // 判定依据必须是数据库实际权限，而不是"变量有没有设置"。
        "has_table_privilege(",
        "has_function_privilege(",
        "RuntimeRoleCanMutateAudit",
        // 单角色部署要么被拒，要么走显式开关并强告警。
        "AllowSingleRole",
        "DegradedButAllowed",
    ] {
        assert!(
            DB_AUDIT_BOUNDARY_MODULE.contains(marker),
            "audit boundary module is missing marker: {marker}"
        );
    }
    // 运行时口令不能被无条件覆盖。
    for marker in ["PasswordAction::Keep", "MIGRATION_MANAGE_RUNTIME_PASSWORD"] {
        assert!(
            DB_ROLES_MODULE.contains(marker),
            "runtime role module is missing marker: {marker}"
        );
    }
    for marker in [
        "SingleRoleNotAllowed",
        "allow-single-role",
        "MIGRATION_DATABASE_URL",
        "AUDIT_ROLE_SEPARATION",
    ] {
        assert!(
            DB_MIGRATE_MODULE.contains(marker),
            "migration plan module is missing marker: {marker}"
        );
    }

    // 校验必须在 migrate 分支里被调用，否则策略只是个没人读的枚举。
    let main = include_str!("../src/main.rs");
    assert!(main.contains("db::MigrationPlan::from_env("));
    assert!(main.contains("db::verify_audit_append_only_boundary("));

    for marker in [
        "AUDIT_ROLE_SEPARATION",
        "MIGRATION_MANAGE_RUNTIME_PASSWORD",
        "allow-single-role",
    ] {
        assert!(
            ENV_EXAMPLE.contains(marker),
            ".env.example must document the audit role separation controls: {marker}"
        );
    }
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
        "docker compose --env-file .env -f docker-compose.prod.yml run --rm --build migrate";
    let start = "docker compose --env-file .env -f docker-compose.prod.yml up -d --build app";
    let migrate_at = INSTALL_SCRIPT
        .find(migrate)
        .expect("installer must run the explicit migration command");
    let start_at = INSTALL_SCRIPT
        .find(start)
        .expect("installer must start the app explicitly");
    assert!(migrate_at < start_at, "migration must precede app startup");
}

#[test]
fn production_app_requires_the_migration_job_to_finish_successfully() {
    let app = PRODUCTION_COMPOSE
        .split_once("  app:\n")
        .map(|(_, rest)| rest)
        .and_then(|rest| rest.split_once("\n  migrate:\n").map(|(app, _)| app))
        .expect("production compose must define app before migrate");
    assert!(
        app.contains("      migrate:\n        condition: service_completed_successfully"),
        "app must not start before the migration job succeeds"
    );

    let migrate = PRODUCTION_COMPOSE
        .split_once("\n  migrate:\n")
        .map(|(_, rest)| rest)
        .and_then(|rest| {
            rest.split_once("\n  postgres:\n")
                .map(|(migrate, _)| migrate)
        })
        .expect("production compose must define migrate before postgres");
    assert!(
        !migrate.contains("profiles:"),
        "the migration dependency must be active during a normal app startup"
    );

    let main = include_str!("../src/main.rs");
    assert!(
        main.contains("db::verify_schema_current(&startup_database).await?;"),
        "the web process must reject a stale migration ledger before constructing application state"
    );
}
