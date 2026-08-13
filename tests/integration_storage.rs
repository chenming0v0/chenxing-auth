#[path = "support/db_isolation.rs"]
mod db_isolation;

use std::{env, time::Duration};

use base64::Engine;
use chenxing_auth::{
    clients::{
        domain::ValidatedClientRegistration,
        repository::{self as client_repository, ClientCredential},
    },
    config::{AuthEncryptionKey, AuthEncryptionKeyRing},
    oauth::{
        code::AuthorizationCode,
        refresh::RefreshToken,
        refresh_store::{RefreshTokenStore, RotationOutcome},
        store::AuthorizationCodeStore,
    },
    sessions::{
        domain::{Session, session_token_hash_bytes},
        store::SessionStore,
    },
    users::{
        credentials::hash_password,
        domain::{UserRole, UserStatus, ValidatedRegistration},
        email::EmailAddress,
        repository::{self as user_repository, NewUser},
    },
};
use redis::AsyncCommands;
use sha2::Digest;
use time::OffsetDateTime;
use uuid::Uuid;

/// 测试夹具的邮箱构造。
///
/// `ValidatedRegistration.email` 是 `EmailAddress`（Issue #302），构造它必须经过
/// 唯一的规范化入口——夹具也不例外，否则测试会绕开被测的那条规则。
fn email_address(raw: impl AsRef<str>) -> EmailAddress {
    let raw = raw.as_ref();
    EmailAddress::parse(raw).unwrap_or_else(|error| panic!("fixture email {raw:?}: {error}"))
}

async fn database() -> chenxing_auth::sqlx::PgPool {
    let database_url = env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://chenxing:chenxing@127.0.0.1:5432/chenxing_auth".to_owned());
    db_isolation::isolated_pool_with_max_connections("integration_storage", &database_url, 4).await
}

fn redis_client() -> redis::Client {
    let url = env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    redis::Client::open(url).expect("Redis URL")
}

#[tokio::test]
async fn postgres_repositories_round_trip_users_and_clients() {
    let pool = database().await;
    let suffix = Uuid::new_v4().simple().to_string();
    let email = format!("storage-{suffix}@example.com");
    let user = user_repository::insert_user(
        &pool,
        ValidatedRegistration {
            username: format!("storage-user-{suffix}"),
            email: email_address(email.clone()),
            password: "correct horse battery".to_owned(),
            display_name: Some("Storage User".to_owned()),
        },
        hash_password("correct horse battery".to_owned())
            .await
            .expect("password hash"),
    )
    .await
    .expect("insert user");

    let credentials = user_repository::find_credentials_by_email(&pool, &email_address(&email))
        .await
        .expect("find credentials")
        .expect("stored credentials");
    assert_eq!(credentials.id, user.id);
    assert_eq!(credentials.email, email);
    assert_eq!(credentials.canonical_email, email.to_ascii_lowercase());

    // Issue #302：按匹配值查找，所以任意等价书写都能命中同一行。
    // 补丁前这条断言会失败：查询比较的是未完全规范化的展示值。
    let uppercase = user_repository::find_credentials_by_email(
        &pool,
        &email_address(email.to_ascii_uppercase()),
    )
    .await
    .expect("find credentials by an equivalent spelling")
    .expect("equivalent spelling must resolve to the same account");
    assert_eq!(uppercase.id, user.id);
    let profile = user_repository::find_profile_by_id(&pool, user.id)
        .await
        .expect("find profile")
        .expect("stored profile");
    assert_eq!(profile.display_name.as_deref(), Some("Storage User"));
    assert!(
        user_repository::find_profile_by_id(&pool, -1)
            .await
            .expect("find missing profile")
            .is_none()
    );

    let client_id = format!("storage-client-{suffix}");
    let client = client_repository::insert_client(
        &pool,
        ValidatedClientRegistration {
            client_name: "Storage Client".to_owned(),
            redirect_uris: vec!["https://storage.example/callback".to_owned()],
            scopes: vec!["openid".to_owned(), "profile".to_owned()],
        },
        client_id.clone(),
        ClientCredential::SecretBasic("client-secret-hash".to_owned()),
    )
    .await
    .expect("insert client");
    let stored = client_repository::find_client_by_id(&pool, &client_id)
        .await
        .expect("find client")
        .expect("stored client");
    assert_eq!(stored.redirect_uris.len(), 1);
    let credentials = client_repository::find_client_credentials(&pool, &client_id)
        .await
        .expect("find client credentials")
        .expect("stored client credentials");
    assert_eq!(
        credentials.client_secret_hash.as_deref(),
        Some("client-secret-hash")
    );
    assert_eq!(credentials.auth_method, "client_secret_basic");
    assert!(
        !client_repository::list_clients(&pool, None, 200, 0)
            .await
            .expect("list clients")
            .is_empty()
    );
    assert!(
        client_repository::update_client(
            &pool,
            None,
            &client_id,
            "Updated Client",
            &["https://storage.example/new-callback".to_owned()],
            &["openid".to_owned()],
        )
        .await
        .expect("update client")
    );
    assert!(
        client_repository::set_client_status(&pool, None, &client_id, "disabled")
            .await
            .expect("disable client")
    );
    assert!(
        client_repository::update_client_secret(&pool, None, &client_id, "new-hash")
            .await
            .expect("update client secret")
    );

    chenxing_auth::sqlx::query("DELETE FROM oauth_clients WHERE id = $1")
        .bind(client.id)
        .execute(&pool)
        .await
        .expect("cleanup client");
    chenxing_auth::sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user.id)
        .execute(&pool)
        .await
        .expect("cleanup user");
}

#[tokio::test]
async fn postgres_transaction_user_insert_and_missing_client_paths_work() {
    let pool = database().await;
    let user = NewUser {
        id: 0,
        username: format!("transaction-user-{}", Uuid::new_v4().simple()),
        email: email_address(format!(
            "transaction-{}@example.com",
            Uuid::new_v4().simple()
        )),
        password_hash: "hash".to_owned(),
        display_name: None,
        role: UserRole::User,
        status: UserStatus::Active,
        created_at: OffsetDateTime::now_utc(),
    };
    let mut transaction = pool.begin().await.expect("begin transaction");
    let user_id = user_repository::insert_user_in_transaction(&mut transaction, &user)
        .await
        .expect("insert user in transaction");
    transaction.commit().await.expect("commit transaction");
    assert!(
        client_repository::find_client_by_id(&pool, "missing-client")
            .await
            .expect("find missing client")
            .is_none()
    );

    chenxing_auth::sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(&pool)
        .await
        .expect("cleanup transaction user");
}

#[tokio::test]
async fn password_change_commits_password_and_session_revocation_together() {
    let pool = database().await;
    let suffix = Uuid::new_v4().simple().to_string();
    let old_password = "correct horse battery";
    let new_password = "new correct password";
    let email = format!("password-commit-{suffix}@example.com");
    let user = user_repository::insert_user(
        &pool,
        ValidatedRegistration {
            username: format!("password-commit-{suffix}"),
            email: email_address(email),
            password: old_password.to_owned(),
            display_name: None,
        },
        hash_password(old_password.to_owned())
            .await
            .expect("old password hash"),
    )
    .await
    .expect("insert user");
    let token_hash = sha2::Sha256::digest(format!("session-{suffix}").as_bytes()).to_vec();
    let created_at = OffsetDateTime::now_utc();
    let session_id: i64 = chenxing_auth::sqlx::query_scalar(
        "INSERT INTO user_sessions (token_hash, user_id, created_at, expires_at)
         VALUES ($1, $2, $3, $4) RETURNING id",
    )
    .bind(&token_hash)
    .bind(user.id)
    .bind(created_at)
    .bind(created_at + time::Duration::hours(1))
    .fetch_one(&pool)
    .await
    .expect("insert session");

    assert_eq!(
        user_repository::change_password_and_revoke_all(
            &pool,
            user.id,
            &hash_password(new_password.to_owned())
                .await
                .expect("new password hash"),
            0,
        )
        .await
        .expect("change password"),
        user_repository::PasswordChangeOutcome::Changed
    );

    let (stored_hash,): (String,) =
        chenxing_auth::sqlx::query_as("SELECT password_hash FROM users WHERE id = $1")
            .bind(user.id)
            .fetch_one(&pool)
            .await
            .expect("stored password hash");
    assert!(
        chenxing_auth::users::credentials::verify_password(
            new_password.to_owned(),
            stored_hash.clone()
        )
        .await
    );
    assert!(
        !chenxing_auth::users::credentials::verify_password(
            old_password.to_owned(),
            stored_hash.clone()
        )
        .await
    );

    let (epoch,): (i64,) =
        chenxing_auth::sqlx::query_as("SELECT session_epoch FROM users WHERE id = $1")
            .bind(user.id)
            .fetch_one(&pool)
            .await
            .expect("session epoch");
    assert_eq!(epoch, 1);
    let (revoked_at,): (Option<OffsetDateTime>,) =
        chenxing_auth::sqlx::query_as("SELECT revoked_at FROM user_sessions WHERE id = $1")
            .bind(session_id)
            .fetch_one(&pool)
            .await
            .expect("revoked session");
    assert!(revoked_at.is_some());
    let outbox: Vec<(String, i64)> = chenxing_auth::sqlx::query_as(
        "SELECT operation, generation FROM session_outbox
         WHERE user_id = $1 ORDER BY id",
    )
    .bind(user.id)
    .fetch_all(&pool)
    .await
    .expect("session outbox");
    assert_eq!(
        outbox,
        vec![
            ("revoke_session".to_owned(), 1),
            ("revoke_user".to_owned(), 1)
        ]
    );

    chenxing_auth::sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user.id)
        .execute(&pool)
        .await
        .expect("cleanup password commit user");
}

#[tokio::test]
async fn password_change_rolls_back_when_session_epoch_update_fails() {
    let pool = database().await;
    let suffix = Uuid::new_v4().simple().to_string();
    let old_password = "correct horse battery";
    let new_password = "new correct password";
    let email = format!("password-rollback-{suffix}@example.com");
    let user = user_repository::insert_user(
        &pool,
        ValidatedRegistration {
            username: format!("password-rollback-{suffix}"),
            email: email_address(email),
            password: old_password.to_owned(),
            display_name: None,
        },
        hash_password(old_password.to_owned())
            .await
            .expect("old password hash"),
    )
    .await
    .expect("insert user");
    let token_hash = sha2::Sha256::digest(format!("rollback-session-{suffix}").as_bytes()).to_vec();
    let created_at = OffsetDateTime::now_utc();
    let session_id: i64 = chenxing_auth::sqlx::query_scalar(
        "INSERT INTO user_sessions (token_hash, user_id, created_at, expires_at)
         VALUES ($1, $2, $3, $4) RETURNING id",
    )
    .bind(&token_hash)
    .bind(user.id)
    .bind(created_at)
    .bind(created_at + time::Duration::hours(1))
    .fetch_one(&pool)
    .await
    .expect("insert session");
    chenxing_auth::sqlx::query("UPDATE users SET session_epoch = $2 WHERE id = $1")
        .bind(user.id)
        .bind(i64::MAX)
        .execute(&pool)
        .await
        .expect("set epoch overflow fixture");

    let result = user_repository::change_password_and_revoke_all(
        &pool,
        user.id,
        &hash_password(new_password.to_owned())
            .await
            .expect("new password hash"),
        // 夹具把 epoch 直接置为 i64::MAX，认证 epoch 必须与之一致，
        // 失败点才落在自增溢出上而不是版本比对上。
        i64::MAX,
    )
    .await;
    assert!(result.is_err(), "epoch overflow must fail the transaction");

    let (stored_hash, epoch): (String, i64) = chenxing_auth::sqlx::query_as(
        "SELECT password_hash, session_epoch FROM users WHERE id = $1",
    )
    .bind(user.id)
    .fetch_one(&pool)
    .await
    .expect("rolled back user state");
    assert!(
        chenxing_auth::users::credentials::verify_password(
            old_password.to_owned(),
            stored_hash.clone()
        )
        .await
    );
    assert!(
        !chenxing_auth::users::credentials::verify_password(
            new_password.to_owned(),
            stored_hash.clone()
        )
        .await
    );
    assert_eq!(epoch, i64::MAX);
    let (revoked_at,): (Option<OffsetDateTime>,) =
        chenxing_auth::sqlx::query_as("SELECT revoked_at FROM user_sessions WHERE id = $1")
            .bind(session_id)
            .fetch_one(&pool)
            .await
            .expect("rolled back session state");
    assert!(revoked_at.is_none());
    let (outbox_count,): (i64,) =
        chenxing_auth::sqlx::query_as("SELECT COUNT(*) FROM session_outbox WHERE user_id = $1")
            .bind(user.id)
            .fetch_one(&pool)
            .await
            .expect("rolled back outbox state");
    assert_eq!(outbox_count, 0);

    chenxing_auth::sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user.id)
        .execute(&pool)
        .await
        .expect("cleanup password rollback user");
}

#[tokio::test]
async fn owned_clients_are_isolated_and_limited_to_two_projects() {
    let pool = database().await;
    let owner = user_repository::insert_user(
        &pool,
        ValidatedRegistration {
            username: format!("owner-{}", Uuid::new_v4().simple()),
            email: email_address(format!("owner-{}@example.com", Uuid::new_v4().simple())),
            password: "correct horse battery".to_owned(),
            display_name: None,
        },
        "hash".to_owned(),
    )
    .await
    .expect("insert owner");
    let other = user_repository::insert_user(
        &pool,
        ValidatedRegistration {
            username: format!("other-{}", Uuid::new_v4().simple()),
            email: email_address(format!("other-{}@example.com", Uuid::new_v4().simple())),
            password: "correct horse battery".to_owned(),
            display_name: None,
        },
        "hash".to_owned(),
    )
    .await
    .expect("insert other owner");

    let registration = || ValidatedClientRegistration {
        client_name: "Owned Client".to_owned(),
        redirect_uris: vec!["https://owned.example/callback".to_owned()],
        scopes: vec!["openid".to_owned()],
    };
    client_repository::insert_owned_client(
        &pool,
        owner.id,
        registration(),
        format!("owned-client-first-{}", Uuid::new_v4().simple()),
        ClientCredential::SecretBasic("hash".to_owned()),
        2,
    )
    .await
    .expect("insert first owned client");
    let (concurrent_a, concurrent_b) = tokio::join!(
        client_repository::insert_owned_client(
            &pool,
            owner.id,
            registration(),
            format!("owned-client-a-{}", Uuid::new_v4().simple()),
            ClientCredential::SecretBasic("hash".to_owned()),
            2,
        ),
        client_repository::insert_owned_client(
            &pool,
            owner.id,
            registration(),
            format!("owned-client-b-{}", Uuid::new_v4().simple()),
            ClientCredential::SecretBasic("hash".to_owned()),
            2,
        ),
    );
    let concurrent_results = [concurrent_a, concurrent_b];
    assert_eq!(
        concurrent_results
            .iter()
            .filter(|result| result.is_ok())
            .count(),
        1
    );
    assert_eq!(
        concurrent_results
            .iter()
            .filter(|result| matches!(
                result,
                Err(client_repository::ClientInsertError::QuotaExceeded)
            ))
            .count(),
        1
    );
    assert_eq!(
        client_repository::list_clients(&pool, Some(owner.id), 200, 0)
            .await
            .expect("list owner clients")
            .len(),
        2
    );
    assert!(
        client_repository::list_clients(&pool, Some(other.id), 200, 0)
            .await
            .expect("list other clients")
            .is_empty()
    );
    assert!(matches!(
        client_repository::insert_owned_client(
            &pool,
            owner.id,
            registration(),
            format!("owned-client-third-{}", Uuid::new_v4().simple()),
            ClientCredential::SecretBasic("hash".to_owned()),
            2,
        )
        .await,
        Err(client_repository::ClientInsertError::QuotaExceeded)
    ));

    let orphan_owner = user_repository::insert_user(
        &pool,
        ValidatedRegistration {
            username: format!("orphan-{}", Uuid::new_v4().simple()),
            email: email_address(format!("orphan-{}@example.com", Uuid::new_v4().simple())),
            password: "correct horse battery".to_owned(),
            display_name: None,
        },
        "hash".to_owned(),
    )
    .await
    .expect("insert orphan owner");
    let orphan_client = client_repository::insert_owned_client(
        &pool,
        orphan_owner.id,
        registration(),
        format!("orphan-client-{}", Uuid::new_v4().simple()),
        ClientCredential::SecretBasic("hash".to_owned()),
        2,
    )
    .await
    .expect("insert orphan client");
    chenxing_auth::sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(orphan_owner.id)
        .execute(&pool)
        .await
        .expect("delete owner");
    assert!(
        client_repository::find_client_by_id(&pool, &orphan_client.client_id)
            .await
            .expect("find deleted client")
            .is_none()
    );

    chenxing_auth::sqlx::query("DELETE FROM users WHERE id IN ($1, $2)")
        .bind(owner.id)
        .bind(other.id)
        .execute(&pool)
        .await
        .expect("cleanup owned clients and users");
}

#[tokio::test]
async fn redis_stores_cover_session_and_one_time_token_lifecycles() {
    let client = redis_client();
    let mut connection = client
        .get_multiplexed_async_connection()
        .await
        .expect("Redis connection");

    let sessions = SessionStore::with_redis_key(client.clone(), [0; 32]);
    let mut session =
        Session::new("storage-user".to_owned(), Duration::from_secs(60)).expect("session");
    let watermark_key = "chenxing:session:revoked-before:storage-user".to_owned();
    let _: usize = connection
        .del(&watermark_key)
        .await
        .expect("clear Redis-only session watermark");
    assert!(
        !connection
            .exists::<_, bool>(&watermark_key)
            .await
            .expect("check missing Redis-only session watermark")
    );
    sessions
        .save(&mut session, Duration::from_secs(60))
        .await
        .expect("save session");
    assert_eq!(
        sessions
            .find(&session.token)
            .await
            .expect("find session")
            .unwrap()
            .id,
        session.id
    );
    let session_hash = session_token_hash_bytes(&session.token);
    let lookup = sessions
        .find_by_token_hash(&session_hash)
        .await
        .expect("find session by hash")
        .expect("hashed session lookup");
    assert_eq!(lookup.id, session.id);
    assert_eq!(lookup.user_id, session.user_id);
    sessions
        .revoke(&session.token)
        .await
        .expect("revoke session");
    assert!(
        sessions
            .find(&session.token)
            .await
            .expect("find revoked session")
            .is_none()
    );
    assert!(
        sessions
            .find_by_token_hash(&session_hash)
            .await
            .expect("find revoked session by hash")
            .is_none()
    );

    let codes = AuthorizationCodeStore::new(client.clone());
    let code = AuthorizationCode::new(
        "storage-client".to_owned(),
        "https://storage.example/callback".to_owned(),
        "storage-user".to_owned(),
        vec!["openid".to_owned()],
        "challenge".to_owned(),
    );
    codes.save(&code).await.expect("save authorization code");
    assert!(codes.find(&code.value).await.expect("find code").is_some());
    let mismatched = AuthorizationCode::new(
        code.client_id.clone(),
        code.redirect_uri.clone(),
        code.user_id.clone(),
        code.scopes.clone(),
        "different-challenge".to_owned(),
    );
    assert!(
        !codes
            .take_if_matches(&code.value, &mismatched)
            .await
            .expect("mismatched code consume")
    );
    assert!(
        codes
            .take_if_matches(&code.value, &code)
            .await
            .expect("matching code consume")
    );
    assert!(
        codes
            .take(&code.value)
            .await
            .expect("take missing code")
            .is_none()
    );
    codes
        .restore(&code, 60)
        .await
        .expect("restore authorization code");
    assert_eq!(
        codes
            .find(&code.value)
            .await
            .expect("find restored code")
            .expect("restored authorization code")
            .value,
        code.value
    );
    codes.take(&code.value).await.expect("remove restored code");

    let refreshes = RefreshTokenStore::new(client);
    let refresh = RefreshToken::new(
        "storage-client".to_owned(),
        "storage-user".to_owned(),
        vec!["openid".to_owned()],
    );
    refreshes.save(&refresh).await.expect("save refresh token");
    assert!(
        refreshes
            .find(&refresh.value)
            .await
            .expect("find refresh")
            .is_some()
    );
    assert!(
        refreshes
            .take_if_matches(&refresh.value, &refresh)
            .await
            .expect("consume refresh token")
    );
    assert!(
        refreshes
            .find(&refresh.value)
            .await
            .expect("find consumed refresh")
            .is_none()
    );
    assert!(
        refreshes
            .read_tombstone(&refresh.value)
            .await
            .expect("read consumed refresh tombstone")
            .is_some(),
        "consuming a refresh token must leave a replay tombstone"
    );

    let rotatable = RefreshToken::new(
        "storage-client".to_owned(),
        "storage-user".to_owned(),
        vec!["openid".to_owned()],
    );
    let rotated = RefreshToken::new(
        rotatable.client_id.clone(),
        rotatable.user_id.clone(),
        rotatable.scopes.clone(),
    );
    let mismatched = RefreshToken::new(
        rotatable.client_id.clone(),
        rotatable.user_id.clone(),
        vec!["profile".to_owned()],
    );
    refreshes
        .save(&rotatable)
        .await
        .expect("save rotatable refresh token");
    assert_eq!(
        refreshes
            .rotate_if_matches(&rotatable.value, &mismatched, &rotated)
            .await
            .expect("mismatched refresh rotation"),
        RotationOutcome::CasMismatch
    );
    assert!(
        refreshes
            .find(&rotatable.value)
            .await
            .expect("find refresh after mismatched rotation")
            .is_some()
    );
    assert_eq!(
        refreshes
            .rotate_if_matches(&rotatable.value, &rotatable, &rotated)
            .await
            .expect("matching refresh rotation"),
        RotationOutcome::Rotated
    );
    assert!(
        refreshes
            .find(&rotatable.value)
            .await
            .expect("find consumed refresh")
            .is_none()
    );
    assert!(
        refreshes
            .find(&rotated.value)
            .await
            .expect("find rotated refresh")
            .is_some()
    );
    // 消费后的旧 token 键已不存在（Issue #312）：store 层如实报告键消失，
    // 是重放还是良性消失由用例层结合墓碑判定。
    assert_eq!(
        refreshes
            .rotate_if_matches(
                &rotatable.value,
                &rotatable,
                &RefreshToken::new(
                    rotatable.client_id.clone(),
                    rotatable.user_id.clone(),
                    rotatable.scopes.clone(),
                )
            )
            .await
            .expect("duplicate refresh rotation"),
        RotationOutcome::KeyMissing
    );

    let session_key = format!(
        "chenxing:session:{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(sha2::Sha256::digest(session.token.as_bytes()))
    );
    let _: usize = connection
        .del(&[
            session_key,
            watermark_key,
            format!(
                "chenxing:oauth:code:{}",
                base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .encode(sha2::Sha256::digest(code.value.as_bytes()))
            ),
            format!("chenxing:oauth:refresh:{}", refresh.value),
            format!("chenxing:oauth:refresh:{}", rotatable.value),
            format!("chenxing:oauth:refresh:{}", rotated.value),
        ])
        .await
        .expect("cleanup Redis keys");
}

#[tokio::test]
async fn session_revocation_generation_rejects_restored_old_payloads() {
    let pool = database().await;
    let user = user_repository::insert_user(
        &pool,
        ValidatedRegistration {
            username: format!("generation-{}", Uuid::new_v4().simple()),
            email: email_address(format!(
                "generation-{}@example.com",
                Uuid::new_v4().simple()
            )),
            password: "correct horse battery".to_owned(),
            display_name: None,
        },
        "hash".to_owned(),
    )
    .await
    .expect("insert generation user");
    let client = redis_client();
    let sessions = SessionStore::with_metadata_and_key(client.clone(), pool.clone(), [0x42; 32]);
    let mut session = Session::new(user.id.to_string(), Duration::from_secs(60)).expect("session");
    sessions
        .save(&mut session, Duration::from_secs(60))
        .await
        .expect("save session");
    sessions
        .revoke_all_for_user(user.id)
        .await
        .expect("revoke all sessions");

    let mut connection = client
        .get_multiplexed_async_connection()
        .await
        .expect("Redis connection");
    let _: () = connection
        .set_ex(
            format!(
                "chenxing:session:{}",
                base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .encode(sha2::Sha256::digest(session.token.as_bytes()))
            ),
            serde_json::to_string(&chenxing_auth::sessions::domain::SessionPayload::from(
                &session,
            ))
            .expect("session JSON"),
            60,
        )
        .await
        .expect("restore old payload");
    assert!(
        sessions
            .find(&session.token)
            .await
            .expect("find restored session")
            .is_none()
    );

    chenxing_auth::sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user.id)
        .execute(&pool)
        .await
        .expect("cleanup generation user");
}

#[tokio::test]
async fn session_find_rejects_metadata_revocation_even_when_redis_payload_exists() {
    let pool = database().await;
    let user = user_repository::insert_user(
        &pool,
        ValidatedRegistration {
            username: format!("metadata-revoke-{}", Uuid::new_v4().simple()),
            email: email_address(format!(
                "metadata-revoke-{}@example.com",
                Uuid::new_v4().simple()
            )),
            password: "correct horse battery".to_owned(),
            display_name: None,
        },
        "hash".to_owned(),
    )
    .await
    .expect("insert metadata revoke user");
    let client = redis_client();
    let sessions = SessionStore::with_metadata_and_key(client, pool.clone(), [0x42; 32]);
    let mut session = Session::new(user.id.to_string(), Duration::from_secs(60)).expect("session");
    sessions
        .save(&mut session, Duration::from_secs(60))
        .await
        .expect("save session");
    chenxing_auth::sqlx::query("UPDATE user_sessions SET revoked_at = NOW() WHERE id = $1")
        .bind(session.id)
        .execute(&pool)
        .await
        .expect("revoke session metadata");

    assert!(
        sessions
            .find(&session.token)
            .await
            .expect("find revoked metadata session")
            .is_none()
    );

    chenxing_auth::sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user.id)
        .execute(&pool)
        .await
        .expect("cleanup metadata revoke user");
}

#[tokio::test]
async fn session_find_uses_database_identity_for_cached_payloads() {
    let pool = database().await;
    let user = user_repository::insert_user(
        &pool,
        ValidatedRegistration {
            username: format!("metadata-identity-{}", Uuid::new_v4().simple()),
            email: email_address(format!(
                "metadata-identity-{}@example.com",
                Uuid::new_v4().simple()
            )),
            password: "correct horse battery".to_owned(),
            display_name: None,
        },
        "hash".to_owned(),
    )
    .await
    .expect("insert metadata identity user");
    let other = user_repository::insert_user(
        &pool,
        ValidatedRegistration {
            username: format!("metadata-other-{}", Uuid::new_v4().simple()),
            email: email_address(format!(
                "metadata-other-{}@example.com",
                Uuid::new_v4().simple()
            )),
            password: "correct horse battery".to_owned(),
            display_name: None,
        },
        "hash".to_owned(),
    )
    .await
    .expect("insert metadata other user");
    let client = redis_client();
    let sessions = SessionStore::with_metadata_and_key(client, pool.clone(), [0x42; 32]);
    let mut session = Session::new(user.id.to_string(), Duration::from_secs(60)).expect("session");
    sessions
        .save(&mut session, Duration::from_secs(60))
        .await
        .expect("save session");
    session.user_id = other.id.to_string();

    let found = sessions
        .find(&session.token)
        .await
        .expect("find cached session")
        .expect("cached session remains valid");
    assert_eq!(found.user_id, user.id.to_string());

    chenxing_auth::sqlx::query("DELETE FROM users WHERE id IN ($1, $2)")
        .bind(user.id)
        .bind(other.id)
        .execute(&pool)
        .await
        .expect("cleanup metadata identity users");
}

#[tokio::test]
async fn session_save_keeps_metadata_pending_when_redis_connection_fails() {
    let pool = database().await;
    let user = user_repository::insert_user(
        &pool,
        ValidatedRegistration {
            username: format!("metadata-connection-failure-{}", Uuid::new_v4().simple()),
            email: email_address(format!(
                "metadata-connection-failure-{}@example.com",
                Uuid::new_v4().simple()
            )),
            password: "correct horse battery".to_owned(),
            display_name: None,
        },
        "hash".to_owned(),
    )
    .await
    .expect("insert metadata connection failure user");

    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("reserve Redis port");
    let port = listener
        .local_addr()
        .expect("reserved Redis address")
        .port();
    drop(listener);
    let redis = redis::Client::open(format!("redis://127.0.0.1:{port}/")).expect("Redis URL");
    let sessions = SessionStore::with_metadata_and_key(redis, pool.clone(), [0x42; 32]);
    let mut session = Session::new(user.id.to_string(), Duration::from_secs(60)).expect("session");

    sessions
        .save(&mut session, Duration::from_secs(60))
        .await
        .expect("database save must not depend on Redis availability");
    assert!(
        session.id > 0,
        "database insert must happen before Redis access"
    );
    assert_eq!(
        chenxing_auth::sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM user_sessions WHERE id = $1",
        )
        .bind(session.id)
        .fetch_one(&pool)
        .await
        .expect("count durable session metadata"),
        1
    );
    assert_eq!(
        chenxing_auth::sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM session_outbox
             WHERE session_id = $1 AND operation = 'sync_session' AND processed_at IS NULL",
        )
        .bind(session.id)
        .fetch_one(&pool)
        .await
        .expect("count pending save outbox"),
        1
    );

    chenxing_auth::sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user.id)
        .execute(&pool)
        .await
        .expect("cleanup metadata connection failure user");
}

fn session_store_key() -> [u8; 32] {
    [0x42; 32]
}

fn session_revocation_marker(user_id: i64) -> String {
    format!("chenxing:session:revoked-epoch:{user_id}")
}

fn session_redis_key(token: &str) -> String {
    format!(
        "chenxing:session:{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(session_token_hash_bytes(token))
    )
}

async fn enqueue_session_sync(pool: &chenxing_auth::sqlx::PgPool, session_id: i64) {
    let result = chenxing_auth::sqlx::query(
        "INSERT INTO session_outbox
             (operation, session_id, user_id, token_hash, generation)
         SELECT 'sync_session', id, user_id, token_hash, session_epoch
         FROM user_sessions
         WHERE id = $1",
    )
    .bind(session_id)
    .execute(pool)
    .await
    .expect("enqueue session sync fixture");
    assert_eq!(result.rows_affected(), 1, "session fixture must exist");
}

fn unavailable_redis_client() -> redis::Client {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("reserve Redis port");
    let port = listener
        .local_addr()
        .expect("reserved Redis address")
        .port();
    drop(listener);
    redis::Client::open(format!("redis://127.0.0.1:{port}/")).expect("Redis URL")
}

#[tokio::test]
async fn session_save_commits_metadata_and_replays_redis_after_connection_failure() {
    let pool = database().await;
    let user = user_repository::insert_user(
        &pool,
        ValidatedRegistration {
            username: format!("outbox-save-{}", Uuid::new_v4().simple()),
            email: email_address(format!(
                "outbox-save-{}@example.com",
                Uuid::new_v4().simple()
            )),
            password: "correct horse battery".to_owned(),
            display_name: None,
        },
        "hash".to_owned(),
    )
    .await
    .expect("insert outbox save user");
    let mut session = Session::new(user.id.to_string(), Duration::from_secs(60)).expect("session");
    let unavailable = SessionStore::with_metadata_and_key(
        unavailable_redis_client(),
        pool.clone(),
        session_store_key(),
    );

    unavailable
        .save(&mut session, Duration::from_secs(60))
        .await
        .expect("database save must not depend on Redis availability");
    assert!(
        unavailable
            .find(&session.token)
            .await
            .expect("find from PostgreSQL authority")
            .is_some()
    );
    assert_eq!(
        chenxing_auth::sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM session_outbox
             WHERE operation = 'sync_session' AND session_id = $1 AND processed_at IS NULL",
        )
        .bind(session.id)
        .fetch_one(&pool)
        .await
        .expect("pending save outbox"),
        1
    );
    assert_eq!(
        unavailable
            .process_pending_outbox()
            .await
            .expect("record failed Redis delivery"),
        0
    );
    let (attempts, has_error): (i32, bool) = chenxing_auth::sqlx::query_as(
        "SELECT attempts, last_error IS NOT NULL
         FROM session_outbox
         WHERE operation = 'sync_session' AND session_id = $1 AND processed_at IS NULL",
    )
    .bind(session.id)
    .fetch_one(&pool)
    .await
    .expect("observable failed save outbox");
    assert_eq!(attempts, 1);
    assert!(has_error);
    chenxing_auth::sqlx::query(
        "UPDATE session_outbox SET available_at = NOW()
         WHERE operation = 'sync_session' AND session_id = $1 AND processed_at IS NULL",
    )
    .bind(session.id)
    .execute(&pool)
    .await
    .expect("make save outbox immediately retryable");

    let available =
        SessionStore::with_metadata_and_key(redis_client(), pool.clone(), session_store_key());
    assert!(
        available
            .process_pending_outbox()
            .await
            .expect("replay save outbox")
            > 0
    );
    assert!(
        available
            .find(&session.token)
            .await
            .expect("find replayed session")
            .is_some()
    );

    chenxing_auth::sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user.id)
        .execute(&pool)
        .await
        .expect("cleanup outbox save user");
}

/// Issue #314：升级期的 active + NULL 行仍以 Redis 作为唯一载荷来源。
#[tokio::test]
async fn session_sync_outbox_preserves_redis_fallback_for_active_null_payload() {
    let pool = database().await;
    let user = user_repository::insert_user(
        &pool,
        ValidatedRegistration {
            username: format!("outbox-null-active-{}", Uuid::new_v4().simple()),
            email: email_address(format!(
                "outbox-null-active-{}@example.com",
                Uuid::new_v4().simple()
            )),
            password: "correct horse battery".to_owned(),
            display_name: None,
        },
        "hash".to_owned(),
    )
    .await
    .expect("insert active NULL-payload user");
    let client = redis_client();
    let store =
        SessionStore::with_metadata_and_key(client.clone(), pool.clone(), session_store_key());
    let mut session = Session::new(user.id.to_string(), Duration::from_secs(300)).expect("session");
    store
        .save(&mut session, Duration::from_secs(300))
        .await
        .expect("save active NULL-payload session");
    store
        .process_pending_outbox()
        .await
        .expect("project initial session payload");

    let redis_key = session_redis_key(&session.token);
    let mut connection = client
        .get_multiplexed_async_connection()
        .await
        .expect("Redis connection");
    let fallback_payload: Vec<u8> = connection
        .get(&redis_key)
        .await
        .expect("initial Redis fallback payload");
    chenxing_auth::sqlx::query("UPDATE user_sessions SET session_payload = NULL WHERE id = $1")
        .bind(session.id)
        .execute(&pool)
        .await
        .expect("simulate pre-backfill session row");
    enqueue_session_sync(&pool, session.id).await;

    assert_eq!(
        store
            .process_pending_outbox()
            .await
            .expect("process active NULL-payload sync"),
        1
    );
    let retained_payload: Option<Vec<u8>> = connection
        .get(&redis_key)
        .await
        .expect("read retained Redis fallback payload");
    assert_eq!(
        retained_payload.as_deref(),
        Some(fallback_payload.as_slice())
    );
    assert!(
        store
            .find(&session.token)
            .await
            .expect("find session through Redis fallback")
            .is_some(),
        "an active migration row must not become a permanent 401"
    );

    let _: usize = connection
        .del(&redis_key)
        .await
        .expect("cleanup active NULL-payload Redis key");
    chenxing_auth::sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user.id)
        .execute(&pool)
        .await
        .expect("cleanup active NULL-payload user");
}

/// Issue #314：NULL 只代表载荷 fallback，不得覆盖 PostgreSQL 的终态判定。
#[tokio::test]
async fn session_sync_outbox_deletes_null_payload_fallbacks_after_revoke_or_expiry() {
    let pool = database().await;
    let user = user_repository::insert_user(
        &pool,
        ValidatedRegistration {
            username: format!("outbox-null-terminal-{}", Uuid::new_v4().simple()),
            email: email_address(format!(
                "outbox-null-terminal-{}@example.com",
                Uuid::new_v4().simple()
            )),
            password: "correct horse battery".to_owned(),
            display_name: None,
        },
        "hash".to_owned(),
    )
    .await
    .expect("insert terminal NULL-payload user");
    let client = redis_client();
    let store =
        SessionStore::with_metadata_and_key(client.clone(), pool.clone(), session_store_key());
    let mut revoked =
        Session::new(user.id.to_string(), Duration::from_secs(300)).expect("revoked session");
    let mut expired =
        Session::new(user.id.to_string(), Duration::from_secs(300)).expect("expired session");
    store
        .save(&mut revoked, Duration::from_secs(300))
        .await
        .expect("save session to revoke");
    store
        .save(&mut expired, Duration::from_secs(300))
        .await
        .expect("save session to expire");
    store
        .process_pending_outbox()
        .await
        .expect("project terminal-state fixtures");

    let revoked_key = session_redis_key(&revoked.token);
    let expired_key = session_redis_key(&expired.token);
    let mut connection = client
        .get_multiplexed_async_connection()
        .await
        .expect("Redis connection");
    assert!(
        connection
            .exists::<_, bool>(&revoked_key)
            .await
            .expect("revoked fixture projection")
    );
    assert!(
        connection
            .exists::<_, bool>(&expired_key)
            .await
            .expect("expired fixture projection")
    );

    chenxing_auth::sqlx::query(
        "UPDATE user_sessions
         SET session_payload = NULL, revoked_at = NOW()
         WHERE id = $1",
    )
    .bind(revoked.id)
    .execute(&pool)
    .await
    .expect("make NULL-payload session revoked");
    chenxing_auth::sqlx::query(
        "UPDATE user_sessions
         SET session_payload = NULL, expires_at = NOW() - INTERVAL '1 second'
         WHERE id = $1",
    )
    .bind(expired.id)
    .execute(&pool)
    .await
    .expect("make NULL-payload session expired");
    enqueue_session_sync(&pool, revoked.id).await;
    enqueue_session_sync(&pool, expired.id).await;

    assert_eq!(
        store
            .process_pending_outbox()
            .await
            .expect("process terminal NULL-payload syncs"),
        2
    );
    assert!(
        !connection
            .exists::<_, bool>(&revoked_key)
            .await
            .expect("revoked fallback deletion"),
        "revocation must win over the NULL-payload fallback"
    );
    assert!(
        !connection
            .exists::<_, bool>(&expired_key)
            .await
            .expect("expired fallback deletion"),
        "expiry must win over the NULL-payload fallback"
    );
    assert!(
        store
            .find(&revoked.token)
            .await
            .expect("find revoked NULL-payload session")
            .is_none()
    );
    assert!(
        store
            .find(&expired.token)
            .await
            .expect("find expired NULL-payload session")
            .is_none()
    );

    chenxing_auth::sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user.id)
        .execute(&pool)
        .await
        .expect("cleanup terminal NULL-payload user");
}

#[tokio::test]
async fn session_outbox_claims_new_events_but_not_future_events() {
    let pool = database().await;
    let user = user_repository::insert_user(
        &pool,
        ValidatedRegistration {
            username: format!("outbox-clock-{}", Uuid::new_v4().simple()),
            email: email_address(format!(
                "outbox-clock-{}@example.com",
                Uuid::new_v4().simple()
            )),
            password: "correct horse battery".to_owned(),
            display_name: None,
        },
        "hash".to_owned(),
    )
    .await
    .expect("insert outbox clock user");
    let store =
        SessionStore::with_metadata_and_key(redis_client(), pool.clone(), session_store_key());

    let mut immediate =
        Session::new(user.id.to_string(), Duration::from_secs(60)).expect("session");
    store
        .save(&mut immediate, Duration::from_secs(60))
        .await
        .expect("save immediate session");
    store
        .process_pending_outbox()
        .await
        .expect("claim immediate outbox event");
    let (attempts, processed): (i32, bool) = chenxing_auth::sqlx::query_as(
        "SELECT attempts, processed_at IS NOT NULL
         FROM session_outbox
         WHERE session_id = $1 AND operation = 'sync_session'",
    )
    .bind(immediate.id)
    .fetch_one(&pool)
    .await
    .expect("observe immediate outbox event");
    assert_eq!(attempts, 1);
    assert!(processed);

    let mut future = Session::new(user.id.to_string(), Duration::from_secs(60)).expect("session");
    store
        .save(&mut future, Duration::from_secs(60))
        .await
        .expect("save future session");
    chenxing_auth::sqlx::query(
        "UPDATE session_outbox
         SET available_at = NOW() + INTERVAL '1 hour'
         WHERE session_id = $1 AND operation = 'sync_session' AND processed_at IS NULL",
    )
    .bind(future.id)
    .execute(&pool)
    .await
    .expect("delay future outbox event");

    store
        .process_pending_outbox()
        .await
        .expect("skip future outbox event");
    let (attempts, processed): (i32, bool) = chenxing_auth::sqlx::query_as(
        "SELECT attempts, processed_at IS NOT NULL
         FROM session_outbox
         WHERE session_id = $1 AND operation = 'sync_session'",
    )
    .bind(future.id)
    .fetch_one(&pool)
    .await
    .expect("observe future outbox event");
    assert_eq!(attempts, 0);
    assert!(!processed);

    chenxing_auth::sqlx::query(
        "UPDATE session_outbox SET available_at = NOW()
         WHERE session_id = $1 AND operation = 'sync_session' AND processed_at IS NULL",
    )
    .bind(future.id)
    .execute(&pool)
    .await
    .expect("release future outbox event");
    store
        .process_pending_outbox()
        .await
        .expect("claim released outbox event");
    let (attempts, processed): (i32, bool) = chenxing_auth::sqlx::query_as(
        "SELECT attempts, processed_at IS NOT NULL
         FROM session_outbox
         WHERE session_id = $1 AND operation = 'sync_session'",
    )
    .bind(future.id)
    .fetch_one(&pool)
    .await
    .expect("observe released outbox event");
    assert_eq!(attempts, 1);
    assert!(processed);

    chenxing_auth::sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user.id)
        .execute(&pool)
        .await
        .expect("cleanup outbox clock user");
}

#[tokio::test]
async fn session_sync_projection_does_not_resurrect_a_concurrently_revoked_row() {
    let pool = database().await;
    let user = user_repository::insert_user(
        &pool,
        ValidatedRegistration {
            username: format!("outbox-race-{}", Uuid::new_v4().simple()),
            email: email_address(format!(
                "outbox-race-{}@example.com",
                Uuid::new_v4().simple()
            )),
            password: "correct horse battery".to_owned(),
            display_name: None,
        },
        "hash".to_owned(),
    )
    .await
    .expect("insert outbox race user");
    let available =
        SessionStore::with_metadata_and_key(redis_client(), pool.clone(), session_store_key());
    let mut session = Session::new(user.id.to_string(), Duration::from_secs(60)).expect("session");
    available
        .save(&mut session, Duration::from_secs(60))
        .await
        .expect("save session");

    let mut lock = pool.begin().await.expect("session row lock transaction");
    chenxing_auth::sqlx::query("SELECT id FROM user_sessions WHERE id = $1 FOR UPDATE")
        .bind(session.id)
        .fetch_one(&mut *lock)
        .await
        .expect("lock session row");
    let worker = tokio::spawn({
        let available = available.clone();
        async move { available.process_pending_outbox().await }
    });
    for _ in 0..50 {
        let attempts: i32 = chenxing_auth::sqlx::query_scalar(
            "SELECT attempts FROM session_outbox WHERE session_id = $1 AND operation = 'sync_session'",
        )
        .bind(session.id)
        .fetch_one(&pool)
        .await
        .expect("observe claimed sync outbox");
        if attempts > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    chenxing_auth::sqlx::query("UPDATE user_sessions SET revoked_at = NOW() WHERE id = $1")
        .bind(session.id)
        .execute(&mut *lock)
        .await
        .expect("revoke locked session row");
    lock.commit().await.expect("commit concurrent revocation");
    worker
        .await
        .expect("join projection worker")
        .expect("process projection outbox");

    let mut connection = redis_client()
        .get_multiplexed_async_connection()
        .await
        .expect("Redis connection");
    let redis_key = format!(
        "chenxing:session:{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(sha2::Sha256::digest(session.token.as_bytes()))
    );
    assert!(
        !connection
            .exists::<_, bool>(&redis_key)
            .await
            .expect("revoked Redis session")
    );

    chenxing_auth::sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user.id)
        .execute(&pool)
        .await
        .expect("cleanup outbox race user");
}

#[tokio::test]
async fn session_revoke_keeps_database_authoritative_until_redis_recovers() {
    let pool = database().await;
    let user = user_repository::insert_user(
        &pool,
        ValidatedRegistration {
            username: format!("outbox-revoke-{}", Uuid::new_v4().simple()),
            email: email_address(format!(
                "outbox-revoke-{}@example.com",
                Uuid::new_v4().simple()
            )),
            password: "correct horse battery".to_owned(),
            display_name: None,
        },
        "hash".to_owned(),
    )
    .await
    .expect("insert outbox revoke user");
    let key = session_store_key();
    let client = redis_client();
    let mut connection = client
        .get_multiplexed_async_connection()
        .await
        .expect("Redis connection");
    let revocation_marker = session_revocation_marker(user.id);
    let _: usize = connection
        .del(&revocation_marker)
        .await
        .expect("clear reused user revocation marker");
    let available = SessionStore::with_metadata_and_key(client, pool.clone(), key);
    let mut session = Session::new(user.id.to_string(), Duration::from_secs(60)).expect("session");
    available
        .save(&mut session, Duration::from_secs(60))
        .await
        .expect("save session");
    available
        .process_pending_outbox()
        .await
        .expect("flush save outbox");

    let unavailable =
        SessionStore::with_metadata_and_key(unavailable_redis_client(), pool.clone(), key);
    unavailable
        .revoke(&session.token)
        .await
        .expect("database revoke must not depend on Redis availability");
    assert!(
        unavailable
            .find(&session.token)
            .await
            .expect("find revoked session")
            .is_none()
    );
    assert_eq!(
        chenxing_auth::sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM session_outbox
             WHERE operation = 'revoke_session' AND token_hash = $1 AND processed_at IS NULL",
        )
        .bind(sha2::Sha256::digest(session.token.as_bytes()).to_vec())
        .fetch_one(&pool)
        .await
        .expect("pending revoke outbox"),
        1
    );

    let redis_key = format!(
        "chenxing:session:{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(sha2::Sha256::digest(session.token.as_bytes()))
    );
    assert!(
        connection
            .exists::<_, bool>(&redis_key)
            .await
            .expect("initial Redis session projection")
    );
    assert!(
        connection
            .exists::<_, bool>(&redis_key)
            .await
            .expect("stale Redis session")
    );
    available
        .process_pending_outbox()
        .await
        .expect("replay revoke outbox");
    assert!(
        !connection
            .exists::<_, bool>(&redis_key)
            .await
            .expect("revoked Redis session")
    );

    chenxing_auth::sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user.id)
        .execute(&pool)
        .await
        .expect("cleanup outbox revoke user");
    let _: usize = connection
        .del(&revocation_marker)
        .await
        .expect("cleanup session revocation marker");
}

#[tokio::test]
async fn session_revoke_for_user_commits_revocation_before_redis_delivery() {
    let pool = database().await;
    let user = user_repository::insert_user(
        &pool,
        ValidatedRegistration {
            username: format!("outbox-single-{}", Uuid::new_v4().simple()),
            email: email_address(format!(
                "outbox-single-{}@example.com",
                Uuid::new_v4().simple()
            )),
            password: "correct horse battery".to_owned(),
            display_name: None,
        },
        "hash".to_owned(),
    )
    .await
    .expect("insert outbox single revoke user");
    let key = session_store_key();
    let available = SessionStore::with_metadata_and_key(redis_client(), pool.clone(), key);
    let mut session = Session::new(user.id.to_string(), Duration::from_secs(60)).expect("session");
    available
        .save(&mut session, Duration::from_secs(60))
        .await
        .expect("save session");
    available
        .process_pending_outbox()
        .await
        .expect("flush save outbox");

    let unavailable =
        SessionStore::with_metadata_and_key(unavailable_redis_client(), pool.clone(), key);
    assert!(
        unavailable
            .revoke_for_user(user.id, session.id)
            .await
            .expect("database single revoke")
    );
    assert!(
        unavailable
            .find(&session.token)
            .await
            .expect("find revoked single session")
            .is_none()
    );
    assert_eq!(
        chenxing_auth::sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM session_outbox
             WHERE operation = 'revoke_session' AND session_id = $1 AND processed_at IS NULL",
        )
        .bind(session.id)
        .fetch_one(&pool)
        .await
        .expect("pending single revoke outbox"),
        1
    );
    available
        .process_pending_outbox()
        .await
        .expect("replay single revoke outbox");

    chenxing_auth::sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user.id)
        .execute(&pool)
        .await
        .expect("cleanup outbox single revoke user");
}

#[tokio::test]
async fn session_revoke_all_commits_all_rows_before_redis_delivery() {
    let pool = database().await;
    let user = user_repository::insert_user(
        &pool,
        ValidatedRegistration {
            username: format!("outbox-all-{}", Uuid::new_v4().simple()),
            email: email_address(format!(
                "outbox-all-{}@example.com",
                Uuid::new_v4().simple()
            )),
            password: "correct horse battery".to_owned(),
            display_name: None,
        },
        "hash".to_owned(),
    )
    .await
    .expect("insert outbox all revoke user");
    let key = session_store_key();
    let available = SessionStore::with_metadata_and_key(redis_client(), pool.clone(), key);
    let mut first =
        Session::new(user.id.to_string(), Duration::from_secs(60)).expect("first session");
    let mut second =
        Session::new(user.id.to_string(), Duration::from_secs(60)).expect("second session");
    available
        .save(&mut first, Duration::from_secs(60))
        .await
        .expect("save first session");
    available
        .save(&mut second, Duration::from_secs(60))
        .await
        .expect("save second session");
    available
        .process_pending_outbox()
        .await
        .expect("flush save outbox");

    let unavailable =
        SessionStore::with_metadata_and_key(unavailable_redis_client(), pool.clone(), key);
    unavailable
        .revoke_all_for_user(user.id)
        .await
        .expect("database batch revoke");
    assert_eq!(
        chenxing_auth::sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM user_sessions
             WHERE user_id = $1 AND revoked_at IS NOT NULL",
        )
        .bind(user.id)
        .fetch_one(&pool)
        .await
        .expect("revoked session metadata"),
        2
    );
    assert_eq!(
        chenxing_auth::sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM session_outbox
             WHERE operation = 'revoke_user' AND user_id = $1 AND processed_at IS NULL",
        )
        .bind(user.id)
        .fetch_one(&pool)
        .await
        .expect("pending batch revoke outbox"),
        1
    );
    assert!(
        unavailable
            .find(&first.token)
            .await
            .expect("find first revoked session")
            .is_none()
    );
    assert!(
        unavailable
            .find(&second.token)
            .await
            .expect("find second revoked session")
            .is_none()
    );
    available
        .process_pending_outbox()
        .await
        .expect("replay batch revoke outbox");

    chenxing_auth::sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user.id)
        .execute(&pool)
        .await
        .expect("cleanup outbox all revoke user");
}

#[tokio::test]
async fn session_revoke_all_outbox_cleans_redis_after_user_deletion() {
    let pool = database().await;
    let user = user_repository::insert_user(
        &pool,
        ValidatedRegistration {
            username: format!("outbox-delete-{}", Uuid::new_v4().simple()),
            email: email_address(format!(
                "outbox-delete-{}@example.com",
                Uuid::new_v4().simple()
            )),
            password: "correct horse battery".to_owned(),
            display_name: None,
        },
        "hash".to_owned(),
    )
    .await
    .expect("insert outbox deletion user");
    let key = session_store_key();
    let client = redis_client();
    let mut connection = client
        .get_multiplexed_async_connection()
        .await
        .expect("Redis connection");
    let revocation_marker = session_revocation_marker(user.id);
    let _: usize = connection
        .del(&revocation_marker)
        .await
        .expect("clear reused user revocation marker");
    let available = SessionStore::with_metadata_and_key(client, pool.clone(), key);
    let mut session = Session::new(user.id.to_string(), Duration::from_secs(60)).expect("session");
    available
        .save(&mut session, Duration::from_secs(60))
        .await
        .expect("save session");
    available
        .process_pending_outbox()
        .await
        .expect("flush save outbox");
    let redis_key = format!(
        "chenxing:session:{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(sha2::Sha256::digest(session.token.as_bytes()))
    );
    assert!(
        connection
            .exists::<_, bool>(&redis_key)
            .await
            .expect("initial Redis session projection")
    );
    assert!(
        !connection
            .exists::<_, bool>(&revocation_marker)
            .await
            .expect("initial session revocation marker")
    );

    let unavailable =
        SessionStore::with_metadata_and_key(unavailable_redis_client(), pool.clone(), key);
    unavailable
        .revoke_all_for_user(user.id)
        .await
        .expect("database batch revoke");
    chenxing_auth::sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user.id)
        .execute(&pool)
        .await
        .expect("delete user with pending revoke outbox");

    assert!(
        connection
            .exists::<_, bool>(&redis_key)
            .await
            .expect("stale Redis session")
    );

    available
        .process_pending_outbox()
        .await
        .expect("replay deletion revoke outbox");
    let deleted = !connection
        .exists::<_, bool>(&redis_key)
        .await
        .expect("deleted Redis session");
    let _: usize = connection
        .del(&revocation_marker)
        .await
        .expect("cleanup session revocation marker");
    assert!(
        deleted,
        "pending revoke outbox must delete the Redis session projection"
    );
}

#[tokio::test]
async fn concurrent_save_and_revoke_all_keep_the_epoch_boundary_monotonic() {
    let pool = database().await;
    let user = user_repository::insert_user(
        &pool,
        ValidatedRegistration {
            username: format!("epoch-race-{}", Uuid::new_v4().simple()),
            email: email_address(format!(
                "epoch-race-{}@example.com",
                Uuid::new_v4().simple()
            )),
            password: "correct horse battery".to_owned(),
            display_name: None,
        },
        "hash".to_owned(),
    )
    .await
    .expect("insert epoch race user");
    let store = SessionStore::with_metadata_and_key(redis_client(), pool.clone(), [0x42; 32]);
    let mut concurrent =
        Session::new(user.id.to_string(), Duration::from_secs(60)).expect("concurrent session");

    let (save_result, revoke_result) = tokio::join!(
        store.save(&mut concurrent, Duration::from_secs(60)),
        store.revoke_all_for_user(user.id),
    );
    save_result.expect("concurrent save");
    revoke_result.expect("concurrent revoke all");

    let sync_id: Option<(i64,)> = chenxing_auth::sqlx::query_as(
        "SELECT id FROM session_outbox
         WHERE session_id = $1 AND operation = 'sync_session'
         ORDER BY id DESC LIMIT 1",
    )
    .bind(concurrent.id)
    .fetch_optional(&pool)
    .await
    .expect("find concurrent sync event");
    if let Some((sync_id,)) = sync_id {
        chenxing_auth::sqlx::query(
            "UPDATE session_outbox
             SET available_at = NOW() + INTERVAL '1 hour'
             WHERE id = $1",
        )
        .bind(sync_id)
        .execute(&pool)
        .await
        .expect("delay sync event");
    }
    store
        .process_pending_outbox()
        .await
        .expect("apply revoke events first");
    if let Some((sync_id,)) = sync_id {
        chenxing_auth::sqlx::query("UPDATE session_outbox SET available_at = NOW() WHERE id = $1")
            .bind(sync_id)
            .execute(&pool)
            .await
            .expect("release delayed sync event");
        store
            .process_pending_outbox()
            .await
            .expect("apply delayed sync event");
    }

    let state: Option<(bool, i64, i64)> = chenxing_auth::sqlx::query_as(
        "SELECT sessions.revoked_at IS NULL, sessions.session_epoch, users.session_epoch
         FROM user_sessions AS sessions
         JOIN users ON users.id = sessions.user_id
         WHERE sessions.id = $1",
    )
    .bind(concurrent.id)
    .fetch_optional(&pool)
    .await
    .expect("read concurrent session state");
    let Some((active, session_epoch, user_epoch)) = state else {
        panic!("concurrent session row missing");
    };
    if active {
        assert!(session_epoch >= user_epoch);
        assert!(
            store
                .find(&concurrent.token)
                .await
                .expect("find current session")
                .is_some()
        );
    } else {
        assert!(
            store
                .find(&concurrent.token)
                .await
                .expect("find revoked session")
                .is_none()
        );
    }

    chenxing_auth::sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user.id)
        .execute(&pool)
        .await
        .expect("cleanup epoch race user");
}

#[tokio::test]
async fn session_projection_is_encrypted_and_old_key_remains_readable() {
    let pool = database().await;
    let user = user_repository::insert_user(
        &pool,
        ValidatedRegistration {
            username: format!("key-ring-{}", Uuid::new_v4().simple()),
            email: email_address(format!("key-ring-{}@example.com", Uuid::new_v4().simple())),
            password: "correct horse battery".to_owned(),
            display_name: None,
        },
        "hash".to_owned(),
    )
    .await
    .expect("insert key ring user");
    let client = redis_client();
    let old_store = SessionStore::with_metadata_and_key(client.clone(), pool.clone(), [2; 32]);
    let mut session = Session::new(user.id.to_string(), Duration::from_secs(60)).expect("session");
    old_store
        .save(&mut session, Duration::from_secs(60))
        .await
        .expect("save old-key session");

    let ring = AuthEncryptionKeyRing::from_entries(
        "current".to_owned(),
        vec![
            ("current".to_owned(), AuthEncryptionKey::new([1; 32])),
            ("previous".to_owned(), AuthEncryptionKey::new([2; 32])),
        ],
    )
    .expect("rotation ring");
    let rotated = SessionStore::with_metadata_and_key_ring(client.clone(), pool.clone(), ring);
    assert!(
        rotated
            .find(&session.token)
            .await
            .expect("read old key")
            .is_some()
    );
    rotated
        .process_pending_outbox()
        .await
        .expect("project encrypted session");

    let mut connection = client
        .get_multiplexed_async_connection()
        .await
        .expect("Redis connection");
    let redis_key = format!(
        "chenxing:session:{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(sha2::Sha256::digest(session.token.as_bytes()))
    );
    let projected: Vec<u8> = connection.get(&redis_key).await.expect("projected payload");
    assert!(
        !projected
            .windows(session.token.len())
            .any(|window| window == session.token.as_bytes())
    );
    assert!(
        !projected
            .windows(session.csrf_token.len())
            .any(|window| window == session.csrf_token.as_bytes())
    );

    let invalid_key = SessionStore::with_metadata_and_key(client, pool.clone(), [3; 32]);
    assert!(
        invalid_key
            .find(&session.token)
            .await
            .expect("invalid key must be controlled")
            .is_none()
    );

    chenxing_auth::sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user.id)
        .execute(&pool)
        .await
        .expect("cleanup key ring user");
}

#[tokio::test]
async fn session_find_renews_idle_activity_without_extending_absolute_expiry() {
    let pool = database().await;
    let user = user_repository::insert_user(
        &pool,
        ValidatedRegistration {
            username: format!("idle-renew-{}", Uuid::new_v4().simple()),
            email: email_address(format!(
                "idle-renew-{}@example.com",
                Uuid::new_v4().simple()
            )),
            password: "correct horse battery".to_owned(),
            display_name: None,
        },
        "hash".to_owned(),
    )
    .await
    .expect("insert idle renewal user");
    let store = SessionStore::with_metadata_and_key(redis_client(), pool.clone(), [0x52; 32])
        .with_session_policy(Duration::from_secs(10), 5);
    let mut session = Session::new_with_idle_timeout(
        user.id.to_string(),
        Duration::from_secs(300),
        Duration::from_secs(10),
    )
    .expect("session");
    let absolute_expiry = session.expires_at;
    store
        .save(&mut session, Duration::from_secs(300))
        .await
        .expect("save idle renewal session");
    chenxing_auth::sqlx::query(
        "UPDATE user_sessions
         SET last_seen_at = NOW() - INTERVAL '6 seconds'
         WHERE id = $1",
    )
    .bind(session.id)
    .execute(&pool)
    .await
    .expect("age session activity");

    let found = store
        .find(&session.token)
        .await
        .expect("find renewed session")
        .expect("renewed session remains active");
    let expiry_difference_nanos = found
        .expires_at
        .unix_timestamp_nanos()
        .abs_diff(absolute_expiry.unix_timestamp_nanos());
    assert!(
        expiry_difference_nanos < 1_000,
        "absolute expiry changed by {expiry_difference_nanos}ns"
    );
    assert!(found.last_seen_at > session.created_at);
    let stored_last_seen: OffsetDateTime =
        chenxing_auth::sqlx::query_scalar("SELECT last_seen_at FROM user_sessions WHERE id = $1")
            .bind(session.id)
            .fetch_one(&pool)
            .await
            .expect("read renewed activity");
    assert!(stored_last_seen > session.created_at);

    chenxing_auth::sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user.id)
        .execute(&pool)
        .await
        .expect("cleanup idle renewal user");
}

#[tokio::test]
async fn session_save_revokes_the_oldest_active_session_at_the_user_cap() {
    let pool = database().await;
    let user = user_repository::insert_user(
        &pool,
        ValidatedRegistration {
            username: format!("session-cap-{}", Uuid::new_v4().simple()),
            email: email_address(format!(
                "session-cap-{}@example.com",
                Uuid::new_v4().simple()
            )),
            password: "correct horse battery".to_owned(),
            display_name: None,
        },
        "hash".to_owned(),
    )
    .await
    .expect("insert session cap user");
    let store = SessionStore::with_metadata_and_key(redis_client(), pool.clone(), [0x53; 32])
        .with_session_policy(Duration::from_secs(3_600), 2);
    let mut first = Session::new_with_idle_timeout(
        user.id.to_string(),
        Duration::from_secs(3_600),
        Duration::from_secs(3_600),
    )
    .expect("first session");
    store
        .save(&mut first, Duration::from_secs(3_600))
        .await
        .expect("save first session");
    let mut second = Session::new_with_idle_timeout(
        user.id.to_string(),
        Duration::from_secs(3_600),
        Duration::from_secs(3_600),
    )
    .expect("second session");
    store
        .save(&mut second, Duration::from_secs(3_600))
        .await
        .expect("save second session");
    let mut third = Session::new_with_idle_timeout(
        user.id.to_string(),
        Duration::from_secs(3_600),
        Duration::from_secs(3_600),
    )
    .expect("third session");
    store
        .save(&mut third, Duration::from_secs(3_600))
        .await
        .expect("save third session");

    let active_count: i64 = chenxing_auth::sqlx::query_scalar(
        "SELECT COUNT(*) FROM user_sessions
         WHERE user_id = $1 AND revoked_at IS NULL",
    )
    .bind(user.id)
    .fetch_one(&pool)
    .await
    .expect("count active session rows");
    assert_eq!(active_count, 2);
    assert!(
        store
            .find(&first.token)
            .await
            .expect("find evicted session")
            .is_none()
    );
    assert!(
        store
            .find(&second.token)
            .await
            .expect("find second")
            .is_some()
    );
    assert!(
        store
            .find(&third.token)
            .await
            .expect("find third")
            .is_some()
    );

    chenxing_auth::sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user.id)
        .execute(&pool)
        .await
        .expect("cleanup session cap user");
}

/// Issue #263：redis-only 路径的用户级撤销水位必须带过期时间。
///
/// 水位 TTL 取绝对 Session TTL。这里同时断言"水位不会先于它应当拦截的会话键消失"：
/// 会话键 TTL 被同一上限封顶，因此 `session_ttl <= watermark_ttl` 必须成立。
#[tokio::test]
async fn redis_only_revocation_watermark_expires_with_the_absolute_session_ttl() {
    let client = redis_client();
    let mut connection = client
        .get_multiplexed_async_connection()
        .await
        .expect("Redis connection");
    let ttl = Duration::from_secs(120);
    let store = SessionStore::with_redis_key(client.clone(), [0x63; 32]).with_absolute_ttl(ttl);
    // redis-only 路径按字符串 user_id 命名水位键，而 revoke_all_for_user 取 i64。
    // 用一个专属高位区间的 ID，避免与 schema 隔离出来的数据库用户共享 Redis 时碰撞。
    let user_id: i64 = 4_263_000_000_000 + i64::from(std::process::id());
    let watermark = format!("chenxing:session:revoked-before:{user_id}");
    let _: usize = connection
        .del(&watermark)
        .await
        .expect("clear watermark before advance");

    let mut session = Session::new(user_id.to_string(), ttl).expect("session");
    store.save(&mut session, ttl).await.expect("save session");
    let session_key = format!(
        "chenxing:session:{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(session_token_hash_bytes(&session.token))
    );
    let session_ttl: i64 = connection
        .ttl(&session_key)
        .await
        .expect("redis-only session key TTL");
    assert!(
        session_ttl > 0 && session_ttl <= 120,
        "session key TTL must stay inside the absolute TTL, got {session_ttl}"
    );

    store
        .revoke_all_for_user(user_id)
        .await
        .expect("advance redis-only watermark");
    let watermark_ttl: i64 = connection
        .ttl(&watermark)
        .await
        .expect("watermark TTL after the advance");
    assert!(
        watermark_ttl > 110 && watermark_ttl <= 120,
        "watermark must expire with the absolute session TTL, got {watermark_ttl}"
    );
    assert!(
        watermark_ttl >= session_ttl,
        "watermark ({watermark_ttl}s) must outlive the session key it rejects ({session_ttl}s)"
    );
    assert!(
        store
            .find(&session.token)
            .await
            .expect("find session behind watermark")
            .is_none(),
        "attaching a TTL must not weaken revocation"
    );

    // 值不前进的分支同样要刷新 TTL：既覆盖乱序撤销，也让升级前留下的无 TTL 老键
    // 被回收。把水位写成远未来的时刻并去掉 TTL，模拟历史老键。
    let future = OffsetDateTime::now_utc() + time::Duration::days(1);
    let legacy_watermark = future.unix_timestamp_nanos().to_string();
    let _: () = connection
        .set(&watermark, &legacy_watermark)
        .await
        .expect("write legacy watermark without a TTL");
    assert_eq!(
        connection
            .ttl::<_, i64>(&watermark)
            .await
            .expect("legacy watermark TTL"),
        -1,
        "legacy watermark fixture must start without a TTL"
    );
    store
        .revoke_all_for_user(user_id)
        .await
        .expect("refresh watermark without advancing it");
    let refreshed_ttl: i64 = connection
        .ttl(&watermark)
        .await
        .expect("watermark TTL after the refresh");
    assert!(
        refreshed_ttl > 110 && refreshed_ttl <= 120,
        "a non-advancing revocation must still attach a TTL, got {refreshed_ttl}"
    );
    assert_eq!(
        connection
            .get::<_, String>(&watermark)
            .await
            .expect("watermark value after refresh"),
        legacy_watermark,
        "refreshing the TTL must not move the watermark backwards"
    );

    // 刷新只延长、不缩短：已经更久的存活窗口不能被砍短。
    let _: bool = connection
        .expire(&watermark, 600)
        .await
        .expect("stretch the watermark TTL");
    store
        .revoke_all_for_user(user_id)
        .await
        .expect("revoke against a longer watermark TTL");
    let preserved_ttl: i64 = connection
        .ttl(&watermark)
        .await
        .expect("watermark TTL after the longer window");
    assert!(
        preserved_ttl > 120,
        "a TTL refresh must never shorten a longer window, got {preserved_ttl}"
    );

    let _: usize = connection
        .del(&[watermark, session_key])
        .await
        .expect("cleanup redis-only watermark keys");
}

/// Issue #263：Postgres + outbox 路径的 `revoked-epoch` 水位同样必须带过期时间。
#[tokio::test]
async fn session_revocation_epoch_marker_expires_with_the_absolute_session_ttl() {
    let pool = database().await;
    let user = user_repository::insert_user(
        &pool,
        ValidatedRegistration {
            username: format!("epoch-ttl-{}", Uuid::new_v4().simple()),
            email: email_address(format!("epoch-ttl-{}@example.com", Uuid::new_v4().simple())),
            password: "correct horse battery".to_owned(),
            display_name: None,
        },
        "hash".to_owned(),
    )
    .await
    .expect("insert epoch ttl user");
    let client = redis_client();
    let mut connection = client
        .get_multiplexed_async_connection()
        .await
        .expect("Redis connection");
    let marker = session_revocation_marker(user.id);
    let _: usize = connection
        .del(&marker)
        .await
        .expect("clear reused user revocation marker");
    let ttl = Duration::from_secs(120);
    let store = SessionStore::with_metadata_and_key(client, pool.clone(), session_store_key())
        .with_absolute_ttl(ttl);
    let mut session = Session::new(user.id.to_string(), ttl).expect("session");
    store.save(&mut session, ttl).await.expect("save session");
    store
        .process_pending_outbox()
        .await
        .expect("flush the save outbox");
    let session_key = format!(
        "chenxing:session:{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(session_token_hash_bytes(&session.token))
    );
    let session_ttl: i64 = connection
        .ttl(&session_key)
        .await
        .expect("projected session key TTL from outbox");
    assert!(
        session_ttl > 0 && session_ttl <= 120,
        "outbox projection TTL must stay inside the absolute TTL, got {session_ttl}"
    );

    store
        .revoke_all_for_user(user.id)
        .await
        .expect("revoke all sessions");
    store
        .process_pending_outbox()
        .await
        .expect("flush revoke outbox");
    let marker_ttl: i64 = connection
        .ttl(&marker)
        .await
        .expect("revocation epoch marker TTL after revoke");
    assert!(
        marker_ttl > 110 && marker_ttl <= 120,
        "the epoch marker must expire with the absolute session TTL, got {marker_ttl}"
    );
    assert!(
        marker_ttl >= session_ttl,
        "marker ({marker_ttl}s) must outlive the projection it rejects ({session_ttl}s)"
    );
    assert!(
        store
            .find(&session.token)
            .await
            .expect("find revoked session")
            .is_none(),
        "attaching a TTL must not weaken revocation"
    );

    // 老键迁移与重复投递：epoch 不前进时也要补 TTL。
    // 写一个高于当前 epoch 的值，强制走"不前进"分支。
    let legacy_marker = "1000000";
    let _: () = connection
        .set(&marker, legacy_marker)
        .await
        .expect("write legacy epoch marker without a TTL");
    assert_eq!(
        connection
            .ttl::<_, i64>(&marker)
            .await
            .expect("legacy epoch marker TTL"),
        -1,
        "legacy marker fixture must start without a TTL"
    );
    store
        .revoke_all_for_user(user.id)
        .await
        .expect("second revoke all");
    store
        .process_pending_outbox()
        .await
        .expect("flush the second revoke outbox");
    let refreshed_ttl: i64 = connection
        .ttl(&marker)
        .await
        .expect("epoch marker TTL after the refresh");
    assert!(
        refreshed_ttl > 110 && refreshed_ttl <= 120,
        "a non-advancing revocation must still attach a TTL, got {refreshed_ttl}"
    );
    assert_eq!(
        connection
            .get::<_, String>(&marker)
            .await
            .expect("marker value after refresh"),
        legacy_marker,
        "refreshing the TTL must not roll the epoch marker backwards"
    );

    chenxing_auth::sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user.id)
        .execute(&pool)
        .await
        .expect("cleanup epoch ttl user");
    let _: usize = connection
        .del(&[marker, session_key])
        .await
        .expect("cleanup epoch ttl keys");
}
