//! Password-change atomicity: credential update and session revocation commit or roll back together.

use super::*;

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
