use chenxing_auth::oauth::quota::OAuthQuotaStore;

#[test]
fn quota_store_can_be_constructed_from_redis_client() {
    let client = redis::Client::open("redis://127.0.0.1:6379").expect("redis URL");
    let _store = OAuthQuotaStore::new(client);
}
