use super::{
    INSTALL_SCRIPT, MANAGE_SCRIPT, PRODUCTION_COMPOSE, REMOTE_COMPOSE, REMOTE_INSTALL_SCRIPT,
    REMOTE_UPDATE_SCRIPT,
};
use std::path::Path;

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

    // 远程安装器拒绝把已有部署当新安装：存在 .env（含符号链接）就移交升级路径。
    assert!(
        REMOTE_INSTALL_SCRIPT.contains("if [[ -e \"$ENV_FILE\" || -L \"$ENV_FILE\" ]]"),
        "remote installer must classify every existing .env path"
    );
    assert!(REMOTE_INSTALL_SCRIPT.contains("检测到已有 .env"));
    // 升级脚本必须在读取任何 .env 值之前完成符号链接拒绝和权限加固。
    let update_symlink = REMOTE_UPDATE_SCRIPT
        .find("[[ ! -L \"$ENV_FILE\" ]]")
        .expect("remote updater must reject a symlinked .env");
    let update_harden = REMOTE_UPDATE_SCRIPT
        .find("chmod 600 -- \"$ENV_FILE\"")
        .expect("remote updater must harden .env permissions");
    let update_first_read = REMOTE_UPDATE_SCRIPT
        .find("read_env_value CHENXING_RELEASE_VERSION")
        .expect("remote updater reads the recorded release");
    assert!(update_symlink < update_first_read);
    assert!(update_harden < update_first_read);
}

#[test]
fn deployment_project_names_are_stable_and_legacy_resolution_fails_closed() {
    assert!(INSTALL_SCRIPT.contains("COMPOSE_PROJECT_NAME"));
    assert!(INSTALL_SCRIPT.contains("resolve_legacy_project"));
    assert!(INSTALL_SCRIPT.contains("docker volume inspect"));
    assert!(INSTALL_SCRIPT.contains("fail closed") || INSTALL_SCRIPT.contains("无法确认"));
    assert!(REMOTE_UPDATE_SCRIPT.contains("ensure_env_value COMPOSE_PROJECT_NAME chenxing-auth"));
    assert!(!REMOTE_INSTALL_SCRIPT.contains("resolve_legacy_project"));
    assert!(!REMOTE_UPDATE_SCRIPT.contains("resolve_legacy_project"));
    let generated = heredoc_body_after(INSTALL_SCRIPT, "    cat > .env <<EOF\n");
    assert!(generated.contains("COMPOSE_PROJECT_NAME="));
    assert!(!INSTALL_SCRIPT.contains("append_env_default COMPOSE_PROJECT_NAME"));
    assert!(REMOTE_INSTALL_SCRIPT.contains("COMPOSE_PROJECT_NAME=chenxing-auth"));
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
        "ghcr.io/${RELEASE_REPOSITORY}:${RELEASE_VERSION}",
        "postgres:16-alpine",
        "redis:7-alpine",
        "docker pull \"$CHENXING_IMAGE\"",
        "docker pull \"$POSTGRES_IMAGE\"",
        "docker pull \"$REDIS_IMAGE\"",
        "compose run --rm migrate",
        "compose up -d app",
        "--debug",
        "管理设置中写入",
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
fn manage_bootstrap_only_downloads_and_dispatches() {
    // 一键安装铁律：manage.sh 是纯引导器。每次运行重新下载 install.sh /
    // update.sh / compose.yml，按 .env 是否存在分发；任何安装/升级业务逻辑
    // （Docker、密钥、迁移、版本解析）都不允许出现在引导器里。
    for marker in [
        "raw.githubusercontent.com/chenming0v0/chenxing-auth/releases",
        "fetch_script install.sh install.sh",
        "fetch_script update.sh update.sh",
        "deploy/compose.yml",
        "bash -n \"$temp_file\"",
        "mktemp",
        "mv -f",
        "exec bash \"$INSTALL_DIR/update.sh\" \"$@\"",
        "exec bash \"$INSTALL_DIR/install.sh\" \"$@\"",
    ] {
        assert!(
            MANAGE_SCRIPT.contains(marker),
            "bootstrap manager is missing marker: {marker}"
        );
    }
    for forbidden in ["docker", "openssl", "migrate", "POSTGRES", "ADMIN_TOKEN"] {
        assert!(
            !MANAGE_SCRIPT.contains(forbidden),
            "bootstrap manager must not contain business logic: {forbidden}"
        );
    }
    // 下载的脚本必须先通过语法校验再原子替换到位。
    let verify_at = MANAGE_SCRIPT
        .find("bash -n \"$temp_file\"")
        .expect("bootstrap must syntax-check downloaded scripts");
    let move_at = MANAGE_SCRIPT
        .find("mv -f -- \"$temp_file\" \"$INSTALL_DIR/$local_name\"")
        .expect("bootstrap must atomically install downloaded scripts");
    assert!(verify_at < move_at);
}

#[test]
fn release_version_resolves_automatically_and_rejects_mutable_tags() {
    // 版本解析在脚本内部完成：默认取最新 Release，用户零输入；
    // CHENXING_RELEASE_VERSION 只用于固定版本或回滚。禁止可变 latest 镜像。
    for script in [REMOTE_INSTALL_SCRIPT, REMOTE_UPDATE_SCRIPT] {
        for marker in [
            "releases/latest",
            "CHENXING_RELEASE_VERSION",
            "^v[0-9]+\\.[0-9]+\\.[0-9]+([.-][0-9A-Za-z.-]+)?$",
            "ghcr.io/${RELEASE_REPOSITORY}:${RELEASE_VERSION}",
        ] {
            assert!(
                script.contains(marker),
                "release resolution is missing marker: {marker}"
            );
        }
        assert!(!script.contains(":latest"));
    }
    // 升级把解析结果写回 .env 作为回滚锚点。
    assert!(
        REMOTE_UPDATE_SCRIPT
            .contains("set_env_value CHENXING_RELEASE_VERSION \"$RELEASE_VERSION\"")
    );
    assert!(REMOTE_UPDATE_SCRIPT.contains("set_env_value CHENXING_IMAGE \"$CHENXING_IMAGE\""));
}

#[test]
fn remote_installer_generates_and_preserves_deployment_secrets() {
    for marker in [
        "openssl rand -base64 32",
        "openssl rand -hex 32",
        "chmod 600 -- \"$ENV_FILE\"",
    ] {
        assert!(
            REMOTE_INSTALL_SCRIPT.contains(marker),
            "remote installer is missing secret marker: {marker}"
        );
    }
    // 升级绝不覆盖 .env 已有值：只允许 ensure（缺失才补），禁止重新生成主密钥。
    for marker in [
        "保留全部已有密钥",
        "ensure_env_value POSTGRES_RUNTIME_PASSWORD",
        "ensure_env_value AUTH_ENCRYPTION_KEYS",
    ] {
        assert!(
            REMOTE_UPDATE_SCRIPT.contains(marker),
            "remote updater is missing preservation marker: {marker}"
        );
    }
    assert!(!REMOTE_UPDATE_SCRIPT.contains("set_env_value AUTH_ENCRYPTION_KEY"));
    assert!(!REMOTE_UPDATE_SCRIPT.contains("set_env_value POSTGRES_PASSWORD"));
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
    }
    assert!(
        INSTALL_SCRIPT.contains("APP_ISSUER=\"$(read_env_value APP_ISSUER)\""),
        "source installer must still read legacy APP_ISSUER from an existing .env"
    );
    assert!(INSTALL_SCRIPT.contains("APP_ISSUER is read only for older deployments"));
    // 远程部署里旧 .env 的 APP_ISSUER 经 Compose 直接透传给应用（数据库设置优先），
    // 升级脚本本身不读它、也不改它。
    assert!(REMOTE_COMPOSE.contains("APP_ISSUER: ${APP_ISSUER-}"));
}

#[test]
fn production_healthchecks_and_installers_use_readiness() {
    let readiness_healthcheck =
        "test: [\"CMD\", \"curl\", \"--fail\", \"http://127.0.0.1:3000/health/ready\"]";
    assert!(PRODUCTION_COMPOSE.contains(readiness_healthcheck));
    assert!(!PRODUCTION_COMPOSE.contains("http://127.0.0.1:3000/health\"]"));
    assert!(INSTALL_SCRIPT.contains("/health/ready"));
    assert!(REMOTE_COMPOSE.contains(readiness_healthcheck));
    for script in [REMOTE_INSTALL_SCRIPT, REMOTE_UPDATE_SCRIPT] {
        let remote_wait = shell_function_body(script, "wait_for_application");
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
}

#[test]
fn remote_installer_reports_full_readiness_timeout_diagnostics() {
    for script in [REMOTE_INSTALL_SCRIPT, REMOTE_UPDATE_SCRIPT] {
        let diagnostics = shell_function_body(script, "report_application_diagnostics");
        for marker in [
            "compose ps >&2 || true",
            "compose logs --no-color --tail=200 app >&2 || true",
        ] {
            assert!(
                diagnostics.contains(marker),
                "readiness diagnostics missing marker: {marker}"
            );
        }
        let (_, timeout_handler) = script
            .split_once("if ! wait_for_application; then\n")
            .expect("remote scripts must handle readiness timeout");
        let timeout_handler = timeout_handler
            .split_once("\nfi\n")
            .map(|(body, _)| body)
            .expect("readiness timeout handler must terminate");
        assert!(timeout_handler.contains("report_application_diagnostics"));
    }
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
    assert!(Path::new("manage.sh").is_file());
    assert!(Path::new("install.sh").is_file());
    assert!(Path::new("update.sh").is_file());
    assert!(Path::new("deploy/compose.yml").is_file());
    assert!(Path::new("docker-compose.prod.yml").is_file());
    assert!(Path::new("Dockerfile").is_file());
    assert!(Path::new("Dockerfile.runtime").is_file());
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
fn remote_manager_pulls_the_release_before_running_migrations() {
    for script in [REMOTE_INSTALL_SCRIPT, REMOTE_UPDATE_SCRIPT] {
        let pull_at = script
            .find("docker pull \"$CHENXING_IMAGE\"")
            .expect("remote scripts must pull the app image");
        let migrate_at = script
            .find("run --rm migrate")
            .expect("remote scripts must run the migration job");
        let start_at = script
            .find("compose up -d app")
            .expect("remote scripts must start the app after migration");
        assert!(pull_at < migrate_at && migrate_at < start_at);
    }
}

#[test]
fn remote_manager_places_curl_output_option_before_the_url() {
    for script in [MANAGE_SCRIPT, REMOTE_INSTALL_SCRIPT, REMOTE_UPDATE_SCRIPT] {
        assert!(script.contains("--connect-timeout 10 -o \"$output\" \"$url\""));
        assert!(!script.contains("--connect-timeout 10 -- \"$url\" -o \"$output\""));
    }
}
