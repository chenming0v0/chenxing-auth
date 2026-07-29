use chenxing_auth::oauth::quota::{
    DAILY_AUTHORIZATION_LIMIT, MONTHLY_AUTHORIZATION_LIMIT, OAuthQuotaStore,
};

#[test]
fn normal_user_oauth_login_limits_are_fixed() {
    assert_eq!(DAILY_AUTHORIZATION_LIMIT, 2_500);
    assert_eq!(MONTHLY_AUTHORIZATION_LIMIT, 50_000);
}

#[test]
fn quota_store_can_be_constructed_from_redis_client() {
    let client = redis::Client::open("redis://127.0.0.1:6379").expect("redis URL");
    let _store = OAuthQuotaStore::new(client);
}
