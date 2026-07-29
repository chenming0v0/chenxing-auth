use std::path::Path;

const BUILD_WORKFLOW: &str = include_str!("../.github/workflows/build.yml");
const INSTALL_SCRIPT: &str = include_str!("../deploy/install.sh");
const DB_MODULE: &str = include_str!("../src/db.rs");

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
}

#[test]
fn database_uses_one_explicit_unified_baseline() {
    assert!(DB_MODULE.contains("unified identity baseline"));
    assert!(DB_MODULE.contains("include_str!(\"../migrations/0001_initial.sql\")"));
    let migrations = std::fs::read_dir("migrations")
        .expect("migrations directory")
        .filter_map(Result::ok)
        .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "sql"))
        .map(|entry| entry.file_name())
        .collect::<Vec<_>>();
    assert_eq!(migrations, vec![std::ffi::OsString::from("0001_initial.sql")]);
}

#[test]
fn application_startup_does_not_mutate_schema_outside_migrations() {
    let main = include_str!("../src/main.rs");
    assert!(main.contains("db::migrate"));
    assert!(!main.contains("CREATE TABLE"));
    assert!(!main.contains("ALTER TABLE"));
}
