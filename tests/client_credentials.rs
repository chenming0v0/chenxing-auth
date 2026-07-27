use chenxing_auth::clients::service::verify_client_secret;
use chenxing_auth::users::credentials::hash_password;

#[test]
fn client_secret_verification_accepts_only_the_original_secret() {
    let hash = hash_password("client-secret-value").expect("secret hash");

    assert!(verify_client_secret("client-secret-value", &hash));
    assert!(!verify_client_secret("wrong-client-secret", &hash));
}
