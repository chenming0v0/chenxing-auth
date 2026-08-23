use chenxing_auth::config::Config;
use chenxing_auth::settings::{
    InitializeIssuerOutcome,
    issuer::{initialize, load, resolve},
};

use crate::db_isolation;

async fn database() -> chenxing_auth::sqlx::PgPool {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://chenxing:chenxing@127.0.0.1:5432/chenxing_auth".to_owned());
    db_isolation::isolated_pool("issuer_settings", &database_url).await
}

#[tokio::test]
async fn issuer_is_initialized_once_and_cannot_be_silently_replaced() {
    let database = database().await;
    assert_eq!(load(&database).await.expect("load empty issuer"), None);

    assert_eq!(
        initialize(&database, "https://auth.example.com/")
            .await
            .expect("initialize issuer"),
        InitializeIssuerOutcome::Created
    );
    assert_eq!(
        load(&database)
            .await
            .expect("load persisted issuer")
            .as_ref()
            .map(|record| record.value.as_str()),
        Some("https://auth.example.com")
    );

    assert_eq!(
        initialize(&database, "https://auth.example.com")
            .await
            .expect("repeat same issuer"),
        InitializeIssuerOutcome::AlreadyConfigured
    );
    assert_eq!(
        initialize(&database, "https://other.example.com")
            .await
            .expect("reject different issuer"),
        InitializeIssuerOutcome::Conflict
    );
    assert_eq!(
        load(&database)
            .await
            .expect("load unchanged issuer")
            .as_ref()
            .map(|record| record.value.as_str()),
        Some("https://auth.example.com")
    );
}

#[tokio::test]
async fn invalid_issuer_is_rejected_without_creating_a_setting() {
    let database = database().await;
    assert!(
        initialize(&database, "https://auth.example.com/path")
            .await
            .is_err()
    );
    assert_eq!(load(&database).await.expect("load empty issuer"), None);
}

#[tokio::test]
async fn runtime_resolution_stays_restricted_until_the_persisted_issuer_exists() {
    let database = database().await;
    let mut config = Config::from_values_with_issuer(
        "127.0.0.1".to_owned(),
        3000,
        "http://127.0.0.1:3000".to_owned(),
        "postgres://localhost/chenxing_auth".to_owned(),
        "redis://localhost".to_owned(),
        3600,
    )
    .expect("config");
    config.issuer = None;

    resolve(&mut config, &database)
        .await
        .expect("resolve unconfigured issuer");
    assert!(config.issuer.is_none());

    initialize(&database, "https://auth.example.com")
        .await
        .expect("initialize issuer");
    resolve(&mut config, &database)
        .await
        .expect("resolve persisted issuer");
    assert_eq!(
        config.issuer.as_ref().map(|issuer| issuer.as_str()),
        Some("https://auth.example.com")
    );
}
