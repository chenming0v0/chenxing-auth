use chenxing_auth::clients::service::verify_client_secret;
use chenxing_auth::users::credentials::hash_password;

/// `hash_password` 在 Issue #122 中改为 async（内部 spawn_blocking），
/// `verify_client_secret` 也在阻塞线程池中执行，因此这里需要 tokio 运行时。
#[tokio::test]
async fn client_secret_verification_accepts_only_the_original_secret() {
    let hash = hash_password("client-secret-value".to_owned())
        .await
        .expect("secret hash");

    assert!(verify_client_secret("client-secret-value", &hash).await);
    assert!(!verify_client_secret("wrong-client-secret", &hash).await);
}
