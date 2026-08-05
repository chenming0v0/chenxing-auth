use chenxing_auth::users::credentials::{hash_password, verify_password};

/// Issue #122：口令哈希与校验的 async 往返。
#[tokio::test]
async fn hashed_password_can_be_verified() {
    let hash = hash_password("correct horse battery".to_owned())
        .await
        .expect("password hash");

    assert!(verify_password("correct horse battery".to_owned(), hash.clone()).await);
    assert!(!verify_password("wrong password".to_owned(), hash).await);
}

#[tokio::test]
async fn empty_password_cannot_be_verified() {
    let hash = hash_password("correct horse battery".to_owned())
        .await
        .expect("password hash");

    assert!(!verify_password(String::new(), hash).await);
}
