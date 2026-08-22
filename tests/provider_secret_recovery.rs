use chenxing_auth::{
    audit::{AuditAction, AuditEvent},
    config::Config,
    oauth::providers::{
        domain::{ClientAuthMethod, ProviderInput},
        secrets::{SecretContext, SecretError, SecretManager},
    },
    settings::{SmtpPasswordAction, SmtpSettingUpdate},
    state::{AppState, StateError},
    users::ManagementActorCredential,
};
use std::{fs, path::PathBuf};
use uuid::Uuid;

#[path = "support/db_isolation.rs"]
mod db_isolation;
#[path = "support/key_directory.rs"]
mod key_directory;

const PROVIDER_KEY_FILE: &str = "oauth-provider-secret.key";

async fn setup(
    label: &str,
    empty_key_directory: bool,
) -> (chenxing_auth::sqlx::PgPool, Config, PathBuf) {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://chenxing:chenxing@127.0.0.1:5432/chenxing_auth".to_owned());
    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    let database = db_isolation::isolated_pool("provider_secret_recovery", &database_url).await;
    let key_directory = if empty_key_directory {
        std::env::temp_dir().join(format!("chenxing-{label}-{}", Uuid::new_v4()))
    } else {
        key_directory::isolated_key_directory(label)
    };
    let mut config = Config::from_values_with_issuer(
        "127.0.0.1".to_owned(),
        3000,
        "http://127.0.0.1:3000".to_owned(),
        database_url,
        redis_url,
        3600,
    )
    .expect("config");
    config.cookie_secure = false;
    config.key_directory = key_directory.to_string_lossy().into_owned();
    (database, config, key_directory)
}

fn assert_missing_key(error: &StateError) {
    assert!(
        matches!(
            error,
            StateError::ExternalOAuthSecret(SecretError::MissingKeyForPersistedSecrets)
        ),
        "unexpected startup error: {error}"
    );
}

fn provider_input() -> ProviderInput {
    ProviderInput {
        name: "Recovery Provider".to_owned(),
        slug: "recovery-provider".to_owned(),
        authorization_endpoint: "https://sso.example.com/oauth/authorize".to_owned(),
        token_endpoint: "https://sso.example.com/oauth/token".to_owned(),
        userinfo_endpoint: "https://sso.example.com/oauth/userinfo".to_owned(),
        client_id: "recovery-client".to_owned(),
        client_secret: Some("recoverable-provider-secret".to_owned()),
        scopes: vec!["openid".to_owned(), "email".to_owned()],
        subject_claim: "sub".to_owned(),
        email_claim: "email".to_owned(),
        name_claim: Some("name".to_owned()),
        email_verified_claim: Some("email_verified".to_owned()),
        client_auth_method: ClientAuthMethod::Basic,
        pkce_enabled: true,
    }
}

#[tokio::test]
async fn empty_database_allows_first_provider_key_generation() {
    let (database, config, key_directory) = setup("provider-secret-bootstrap", true).await;

    let state = AppState::new_with_pool(config, database)
        .await
        .expect("empty database may bootstrap provider key");

    assert!(key_directory.join(PROVIDER_KEY_FILE).is_file());
    drop(state);
    let _ = fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn provider_ciphertext_blocks_replacement_key_and_accepts_restored_key() {
    let (database, config, key_directory) = setup("provider-secret-provider", false).await;
    let key_path = key_directory.join(PROVIDER_KEY_FILE);
    let original_key = fs::read(&key_path).expect("read provider key recovery fixture");
    let state = AppState::new_with_pool(config.clone(), database.clone())
        .await
        .expect("initial state");
    state
        .external_oauth
        .create_with_audit(
            provider_input(),
            ManagementActorCredential::SystemToken,
            AuditEvent::new(
                "system_token".to_owned(),
                None,
                AuditAction::OauthProviderCreate,
                "oauth_provider".to_owned(),
                Some("recovery-provider".to_owned()),
                serde_json::json!({"test": "provider_secret_recovery"}),
            ),
        )
        .await
        .expect("persist encrypted provider secret");
    let (provider_id, ciphertext): (i64, Vec<u8>) = chenxing_auth::sqlx::query_as(
        "SELECT id, client_secret_ciphertext
         FROM oauth_providers
         WHERE slug = 'recovery-provider'",
    )
    .fetch_one(&database)
    .await
    .expect("stored provider ciphertext");
    drop(state);
    fs::remove_file(&key_path).expect("simulate lost provider key");

    let error = AppState::new_with_pool(config.clone(), database.clone())
        .await
        .err()
        .expect("missing provider key must fail startup");
    assert_missing_key(&error);
    assert!(
        !key_path.exists(),
        "startup must not create a replacement key"
    );

    fs::write(&key_path, original_key).expect("restore original provider key");
    let manager =
        SecretManager::load_or_generate(&key_directory, true).expect("load restored provider key");
    assert_eq!(
        manager
            .decrypt_for(SecretContext::Provider(provider_id), &ciphertext)
            .expect("decrypt stored provider secret"),
        "recoverable-provider-secret"
    );
    let recovered = AppState::new_with_pool(config, database)
        .await
        .expect("startup after restoring original provider key");
    drop((manager, recovered));
    let _ = fs::remove_dir_all(key_directory);
}

#[tokio::test]
async fn smtp_ciphertext_blocks_replacement_key_and_accepts_restored_key() {
    let (database, config, key_directory) = setup("provider-secret-smtp", false).await;
    let key_path = key_directory.join(PROVIDER_KEY_FILE);
    let original_key = fs::read(&key_path).expect("read SMTP key recovery fixture");
    let state = AppState::new_with_pool(config.clone(), database.clone())
        .await
        .expect("initial state");
    state
        .settings
        .set_smtp(SmtpSettingUpdate {
            host: "smtp.example.com".to_owned(),
            port: 587,
            username: "noreply@example.com".to_owned(),
            from_address: "noreply@example.com".to_owned(),
            ssl_enabled: true,
            force_auth_login: false,
            password_action: Some(SmtpPasswordAction::Set),
            password: Some("recoverable-smtp-password".to_owned()),
        })
        .await
        .expect("persist encrypted SMTP password");
    drop(state);
    fs::remove_file(&key_path).expect("simulate lost provider key");

    let error = AppState::new_with_pool(config.clone(), database.clone())
        .await
        .err()
        .expect("missing key with SMTP ciphertext must fail startup");
    assert_missing_key(&error);
    assert!(
        !key_path.exists(),
        "startup must not create a replacement key"
    );

    fs::write(&key_path, original_key).expect("restore original provider key");
    let recovered = AppState::new_with_pool(config, database)
        .await
        .expect("startup after restoring SMTP encryption key");
    assert!(
        recovered
            .settings
            .smtp()
            .await
            .expect("load restored SMTP setting")
            .password_configured
    );
    drop(recovered);
    let _ = fs::remove_dir_all(key_directory);
}
