use chenxing_auth::oauth::quota::{OAuthQuotaStore, QuotaConsumeResult};
use chenxing_auth::{
    oauth::{
        consent::PendingAuthorization, rate_limit::QpsRateLimiter, refresh::RefreshToken,
        refresh_store::RefreshTokenStore, request_store::AuthorizationRequestStore,
        revocation::TokenRevocationStore,
    },
    plans::domain::AuthQuotaLimits,
    redis_keyspace::RedisKeyspace,
};
use uuid::Uuid;

fn redis_client() -> redis::Client {
    let url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    redis::Client::open(url).expect("Redis URL")
}

#[tokio::test]
async fn oauth_keys_with_identical_ids_are_isolated_by_namespace() {
    let suffix = Uuid::new_v4().simple().to_string();
    let first =
        RedisKeyspace::new(&format!("isolation-a-{suffix}")).expect("first Redis namespace");
    let second =
        RedisKeyspace::new(&format!("isolation-b-{suffix}")).expect("second Redis namespace");
    let client = redis_client();

    let requests_a = AuthorizationRequestStore::with_keyspace(client.clone(), first.clone());
    let requests_b = AuthorizationRequestStore::with_keyspace(client.clone(), second.clone());
    let request = PendingAuthorization {
        request_id: format!("request-{suffix}"),
        client_id: format!("client-{suffix}"),
        redirect_uri: "https://client.example/callback".to_owned(),
        scope: "openid".to_owned(),
        state: "state".to_owned(),
        nonce: None,
        code_challenge: "challenge".to_owned(),
        code_challenge_method: "S256".to_owned(),
        session_token_hash: None,
        holder_hash: None,
        cas_revision: 0,
    };
    requests_a.save(&request).await.expect("save request in A");
    assert!(
        requests_b
            .find(&request.request_id)
            .await
            .expect("find in B")
            .is_none()
    );
    requests_b.save(&request).await.expect("save request in B");
    assert!(
        requests_a
            .find(&request.request_id)
            .await
            .expect("find in A")
            .is_some()
    );
    requests_a
        .take(&request.request_id)
        .await
        .expect("cleanup A request");
    requests_b
        .take(&request.request_id)
        .await
        .expect("cleanup B request");

    let refreshes_a = RefreshTokenStore::with_keyspace(client.clone(), first.clone());
    let refreshes_b = RefreshTokenStore::with_keyspace(client.clone(), second.clone());
    let mut token = RefreshToken::new(
        request.client_id.clone(),
        "same-user".to_owned(),
        vec!["openid".to_owned()],
    );
    token.value = format!("same-token-{suffix}");
    refreshes_a.save(&token).await.expect("save refresh in A");
    assert!(
        refreshes_b
            .find(&token.value)
            .await
            .expect("find refresh in B")
            .is_none()
    );
    refreshes_b.save(&token).await.expect("save refresh in B");
    assert!(
        refreshes_a
            .find(&token.value)
            .await
            .expect("find refresh in A")
            .is_some()
    );
    refreshes_a
        .revoke_family_on_explicit_revoke(
            &token.family_id,
            &token.client_id,
            &token.user_id,
            &token.value,
        )
        .await
        .expect("revoke refresh family in A");
    assert!(
        refreshes_a
            .find(&token.value)
            .await
            .expect("find revoked refresh in A")
            .is_none()
    );
    assert!(
        refreshes_b
            .find(&token.value)
            .await
            .expect("find live refresh in B")
            .is_some()
    );
    assert!(
        refreshes_a
            .read_tombstone(&token.value)
            .await
            .expect("read A tombstone")
            .is_some()
    );
    assert!(
        refreshes_b
            .read_tombstone(&token.value)
            .await
            .expect("read B tombstone")
            .is_none()
    );
    refreshes_b
        .remove(&token.value)
        .await
        .expect("cleanup B refresh");

    let revocations_a = TokenRevocationStore::with_keyspace(client.clone(), first.clone());
    let revocations_b = TokenRevocationStore::with_keyspace(client.clone(), second.clone());
    let access_token = format!("same-access-token-{suffix}");
    revocations_a
        .revoke(&access_token, 60)
        .await
        .expect("revoke access token in A");
    assert!(
        revocations_a
            .is_revoked(&access_token)
            .await
            .expect("read A revocation")
    );
    assert!(
        !revocations_b
            .is_revoked(&access_token)
            .await
            .expect("read B revocation")
    );

    let quotas_a = OAuthQuotaStore::with_keyspace(client.clone(), first.clone());
    let quotas_b = OAuthQuotaStore::with_keyspace(client.clone(), second.clone());
    let limits = AuthQuotaLimits {
        daily_auth_limit: 1,
        monthly_auth_limit: Some(1),
    };
    assert_eq!(
        quotas_a
            .consume_with_limits(&request.client_id, limits)
            .await
            .expect("first A quota use"),
        QuotaConsumeResult::Allowed
    );
    assert_eq!(
        quotas_a
            .consume_with_limits(&request.client_id, limits)
            .await
            .expect("second A quota use"),
        QuotaConsumeResult::DailyExceeded
    );
    assert_eq!(
        quotas_b
            .consume_with_limits(&request.client_id, limits)
            .await
            .expect("first B quota use"),
        QuotaConsumeResult::Allowed
    );

    let qps_a = QpsRateLimiter::with_keyspace(client.clone(), first);
    let qps_b = QpsRateLimiter::with_keyspace(client, second);
    assert!(
        qps_a
            .allow(&request.client_id, 1)
            .await
            .expect("first A request")
    );
    assert!(
        !qps_a
            .allow(&request.client_id, 1)
            .await
            .expect("second A request")
    );
    assert!(
        qps_b
            .allow(&request.client_id, 1)
            .await
            .expect("first B request")
    );
}
