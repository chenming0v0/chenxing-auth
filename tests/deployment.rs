use std::path::Path;

const BUILD_WORKFLOW: &str = include_str!("../.github/workflows/build.yml");
const INSTALL_SCRIPT: &str = include_str!("../deploy/install.sh");
const DB_MODULE: &str = include_str!("../src/db.rs");
const DOCKERFILE: &str = include_str!("../Dockerfile");
const RUNTIME_DOCKERFILE: &str = include_str!("../Dockerfile.runtime");

#[test]
fn release_workflow_publishes_versioned_archives_and_checksums() {
    for marker in [
        "actions/download-artifact@v4",
        "softprops/action-gh-release@v2",
        "SHA256SUMS",
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
        "Dockerfile.runtime",
        "container-binaries/amd64",
        "container-binaries/arm64",
        "binary-x86_64-unknown-linux-gnu",
        "binary-aarch64-unknown-linux-gnu",
        "platforms: linux/amd64,linux/arm64",
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
fn deployment_files_are_present_at_repository_root() {
    assert!(Path::new(".github/workflows/build.yml").is_file());
    assert!(Path::new("deploy/install.sh").is_file());
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
        ]
    );
}

#[test]
fn application_startup_does_not_mutate_schema_outside_migrations() {
    let main = include_str!("../src/main.rs");
    assert!(main.contains("\"migrate\""));
    assert!(!main.contains("db::migrate(&state.database)"));
    assert!(!main.contains("CREATE TABLE"));
    assert!(!main.contains("ALTER TABLE"));
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
