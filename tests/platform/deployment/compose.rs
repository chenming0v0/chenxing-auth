use super::{
    CI_WORKFLOW, ENV_EXAMPLE, INSTALL_SCRIPT, PRODUCTION_COMPOSE, REDIS_CRASH_RECOVERY_SCRIPT,
    REMOTE_COMPOSE, REMOTE_INSTALL_SCRIPT, REMOTE_UPDATE_SCRIPT,
};

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
    // migrate 不再挂在 profile 后面：app 通过 depends_on 等待它完成，
    // production_app_requires_the_migration_job_to_finish_successfully
    // 负责断言 profiles 缺席，这里只校验凭据分离所需的标记。
    for marker in [
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
    assert!(REMOTE_UPDATE_SCRIPT.contains("run --rm migrate"));
    for script in [INSTALL_SCRIPT, REMOTE_INSTALL_SCRIPT, REMOTE_UPDATE_SCRIPT] {
        assert!(!script.contains("run --rm app migrate"));
    }
    assert!(REMOTE_COMPOSE.contains("  migrate:\n"));
    let generated = REMOTE_COMPOSE
        .split_once("services:\n")
        .map(|(_, body)| body)
        .expect("deployment compose must define services");
    let generated_app_start = generated
        .find("  app:")
        .expect("deployment compose must define app");
    let generated_app_end = generated
        .find("\n  migrate:")
        .expect("deployment compose must define migrate after app");
    let generated_app = &generated[generated_app_start..generated_app_end];
    assert!(!generated_app.contains("env_file:"));
    assert!(!generated_app.contains("MIGRATION_DATABASE_URL:"));
}

#[test]
fn compose_keeps_container_listener_fixed_when_host_port_changes() {
    for compose in [PRODUCTION_COMPOSE, REMOTE_COMPOSE] {
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
fn production_redis_has_durable_credential_state_and_crash_coverage() {
    for compose in [PRODUCTION_COMPOSE, REMOTE_COMPOSE] {
        let compose = compose.replace("\r\n", "\n");
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
        REMOTE_UPDATE_SCRIPT.contains("ensure_env_value REDIS_NAMESPACE legacy"),
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
    for script in [REMOTE_INSTALL_SCRIPT, REMOTE_UPDATE_SCRIPT, INSTALL_SCRIPT] {
        assert!(!script.contains("REDIS_NAMESPACE=production"));
        assert!(!script.contains("REDIS_NAMESPACE=${REDIS_NAMESPACE:-production}"));
    }
}

#[test]
fn production_app_requires_the_migration_job_to_finish_successfully() {
    let production_compose = PRODUCTION_COMPOSE.replace("\r\n", "\n");
    let app = production_compose
        .split_once("  app:\n")
        .map(|(_, rest)| rest)
        .and_then(|rest| rest.split_once("\n  migrate:\n").map(|(app, _)| app))
        .expect("production compose must define app before migrate");
    assert!(
        app.contains("      migrate:\n        condition: service_completed_successfully"),
        "app must not start before the migration job succeeds"
    );

    let migrate = production_compose
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

    let main = include_str!("../../../src/main.rs");
    assert!(
        main.contains("db::verify_schema_current(&startup_database).await?;"),
        "the web process must reject a stale migration ledger before constructing application state"
    );
}
