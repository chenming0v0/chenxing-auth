//! PostgreSQL repository round-trips for users, credentials, transactions and clients.

use super::*;

#[tokio::test]
async fn postgres_repositories_round_trip_users_and_clients() {
    let pool = template_database().await;
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
            logo_uri: None,
            client_uri: None,
            description: None,
        },
        client_id.clone(),
        ClientCredential::SecretBasic("client-secret-hash".to_owned()),
        None,
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
            &ValidatedClientRegistration {
                client_name: "Updated Client".to_owned(),
                redirect_uris: vec!["https://storage.example/new-callback".to_owned()],
                scopes: vec!["openid".to_owned()],
                logo_uri: None,
                client_uri: None,
                description: None,
            },
        )
        .await
        .expect("update client")
    );
    assert!(
        client_repository::update_client_secret(&pool, None, &client_id, "new-hash")
            .await
            .expect("update client secret")
    );
    assert!(
        client_repository::set_client_status(&pool, None, &client_id, "disabled")
            .await
            .expect("disable client")
    );
    // Issue #416：已禁用 Client 拒绝轮换 Secret，与认证路径 status 门对齐；
    // 仓库层以 Ok(false) 表达「没有可轮换的版本」。
    assert!(
        !client_repository::update_client_secret(&pool, None, &client_id, "post-disable-hash")
            .await
            .expect("update client secret on disabled client")
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
    let pool = template_database().await;
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

async fn template_database() -> chenxing_auth::sqlx::PgPool {
    let database_url = env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://chenxing:chenxing@127.0.0.1:5432/chenxing_auth".to_owned());
    db_isolation::isolated_pool_from_template_with_max_connections(
        "integration_storage",
        &database_url,
        4,
    )
    .await
}
