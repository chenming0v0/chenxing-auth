use chenxing_auth::users::credentials::{hash_password, verify_password};

#[test]
fn hashed_password_can_be_verified() {
    let hash = hash_password("correct horse battery").expect("password hash");

    assert!(verify_password("correct horse battery", &hash));
    assert!(!verify_password("wrong password", &hash));
}

#[test]
fn empty_password_cannot_be_verified() {
    let hash = hash_password("correct horse battery").expect("password hash");

    assert!(!verify_password("", &hash));
}
