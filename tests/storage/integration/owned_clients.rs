//! Owned-client isolation, project cap and quota re-check under a concurrent plan downgrade.

use super::*;

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
        logo_uri: None,
        client_uri: None,
        description: None,
    };
    client_repository::insert_owned_client(
        &pool,
        owner.id,
        registration(),
        format!("owned-client-first-{}", Uuid::new_v4().simple()),
        ClientCredential::SecretBasic("hash".to_owned()),
    )
    .await
    .expect("insert first owned client")
    .expect("default plan enables owned client creation");
    let (concurrent_a, concurrent_b) = tokio::join!(
        client_repository::insert_owned_client(
            &pool,
            owner.id,
            registration(),
            format!("owned-client-a-{}", Uuid::new_v4().simple()),
            ClientCredential::SecretBasic("hash".to_owned()),
        ),
        client_repository::insert_owned_client(
            &pool,
            owner.id,
            registration(),
            format!("owned-client-b-{}", Uuid::new_v4().simple()),
            ClientCredential::SecretBasic("hash".to_owned()),
        ),
    );
    let concurrent_results = [concurrent_a, concurrent_b];
    assert_eq!(
        concurrent_results
            .iter()
            .filter(|result| matches!(result, Ok(Some(_))))
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
    )
    .await
    .expect("insert orphan client")
    .expect("default plan enables orphan client creation");
    chenxing_auth::sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(orphan_owner.id)
        .execute(&pool)
        .await
        .expect("delete owner");
    assert!(
        client_repository::find_client_by_id(&pool, &orphan_client.client.client_id)
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
async fn owned_client_creation_reloads_quota_after_a_barriered_plan_downgrade() {
    let pool = database().await;
    let owner = user_repository::insert_user(
        &pool,
        ValidatedRegistration {
            username: format!("quota-race-{}", Uuid::new_v4().simple()),
            email: email_address(format!(
                "quota-race-{}@example.com",
                Uuid::new_v4().simple()
            )),
            password: "correct horse battery".to_owned(),
            display_name: None,
        },
        "hash".to_owned(),
    )
    .await
    .expect("insert quota race owner");
    let plan_id: i64 = chenxing_auth::sqlx::query_scalar(
        "INSERT INTO plans (code, name, description, oauth_clients_limit, daily_auth_limit,
                            monthly_auth_limit, max_qps, is_default, status)
         VALUES ($1, 'quota race', NULL, 10, 2500, 50000, NULL, FALSE, 'active')
         RETURNING id",
    )
    .bind(format!("quota-race-{}", Uuid::new_v4().simple()))
    .fetch_one(&pool)
    .await
    .expect("insert quota race plan");
    chenxing_auth::sqlx::query("UPDATE users SET plan_id = $2 WHERE id = $1")
        .bind(owner.id)
        .bind(plan_id)
        .execute(&pool)
        .await
        .expect("assign quota race plan");

    let registration = || ValidatedClientRegistration {
        client_name: "Quota race client".to_owned(),
        redirect_uris: vec!["https://quota-race.example/callback".to_owned()],
        scopes: vec!["openid".to_owned()],
        logo_uri: None,
        client_uri: None,
        description: None,
    };
    client_repository::insert_owned_client(
        &pool,
        owner.id,
        registration(),
        format!("quota-race-existing-{}", Uuid::new_v4().simple()),
        ClientCredential::SecretBasic("hash".to_owned()),
    )
    .await
    .expect("insert existing quota race client");

    // This is the stale value the old handler carried into the repository.
    let stale_limit: i32 =
        chenxing_auth::sqlx::query_scalar("SELECT oauth_clients_limit FROM plans WHERE id = $1")
            .bind(plan_id)
            .fetch_one(&pool)
            .await
            .expect("read stale quota");
    assert_eq!(stale_limit, 10);

    let barrier = Arc::new(tokio::sync::Barrier::new(2));
    let downgrade_pool = pool.clone();
    let downgrade_barrier = barrier.clone();
    let downgrade = tokio::spawn(async move {
        downgrade_barrier.wait().await;
        let mut transaction = downgrade_pool.begin().await.expect("downgrade transaction");
        chenxing_auth::sqlx::query("UPDATE plans SET oauth_clients_limit = 1 WHERE id = $1")
            .bind(plan_id)
            .execute(&mut *transaction)
            .await
            .expect("downgrade plan");
        transaction.commit().await.expect("commit downgrade");
    });
    barrier.wait().await;
    downgrade.await.expect("downgrade task");

    let result = client_repository::insert_owned_client(
        &pool,
        owner.id,
        registration(),
        format!("quota-race-overflow-{}", Uuid::new_v4().simple()),
        ClientCredential::SecretBasic("hash".to_owned()),
    )
    .await;
    assert!(matches!(
        result,
        Err(client_repository::ClientInsertError::QuotaExceeded)
    ));
    let client_count: i64 = chenxing_auth::sqlx::query_scalar(
        "SELECT COUNT(*) FROM oauth_clients WHERE owner_user_id = $1",
    )
    .bind(owner.id)
    .fetch_one(&pool)
    .await
    .expect("quota race client count");
    assert_eq!(
        client_count, 1,
        "the stale limit must not allow an overflow row"
    );

    chenxing_auth::sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(owner.id)
        .execute(&pool)
        .await
        .expect("cleanup quota race owner");
}
