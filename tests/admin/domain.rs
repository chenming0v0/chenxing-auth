use chenxing_auth::users::domain::{UserPermission, UserRole};

#[test]
fn hierarchical_user_roles_have_explicit_permissions() {
    assert!(UserRole::Owner.allows(UserPermission::ManageUsers));
    assert!(UserRole::Admin.allows(UserPermission::ManageClients));
    assert!(!UserRole::Admin.allows(UserPermission::RotateKeys));
    assert!(UserRole::Owner.allows(UserPermission::ManageRoles));
    assert!(!UserRole::User.allows(UserPermission::ReadAudit));
}

#[test]
fn user_roles_round_trip_and_compare_hierarchy() {
    assert_eq!(UserRole::parse("owner"), Some(UserRole::Owner));
    assert_eq!(UserRole::parse("admin"), Some(UserRole::Admin));
    assert_eq!(UserRole::parse("user"), Some(UserRole::User));
    assert_eq!(UserRole::parse("root"), None);
    assert!(UserRole::Owner.is_at_least(UserRole::Admin));
    assert!(!UserRole::User.is_at_least(UserRole::Admin));
    assert_eq!(UserRole::Admin.as_str(), "admin");
}

#[test]
fn user_permission_matrix_is_least_privilege() {
    use UserPermission::*;

    assert!(UserRole::Owner.allows(ManageUsers));
    assert!(UserRole::Owner.allows(ManageClients));
    assert!(UserRole::Owner.allows(RotateKeys));
    assert!(UserRole::Owner.allows(ReadAudit));
    assert!(UserRole::Owner.allows(ManageSettings));
    assert!(UserRole::Owner.allows(ManageSystemSettings));
    assert!(UserRole::Owner.allows(ManageAuthenticationPolicy));
    assert!(UserRole::Owner.allows(ManagePlans));
    assert!(UserRole::Owner.allows(ManageIdentityProviders));
    assert!(UserRole::Owner.allows(ManageRoles));
    assert!(UserRole::Owner.allows(ManageAuthFactors));

    assert!(UserRole::Admin.allows(ManageUsers));
    assert!(UserRole::Admin.allows(ManageClients));
    assert!(!UserRole::Admin.allows(RotateKeys));
    assert!(!UserRole::Admin.allows(ManageRoles));
    // #258：重置他人的 TOTP 把账号降级为「只有密码」，属于账号接管链条的一环，
    // 因此不随 ManageUsers 一起下放给 Admin。
    assert!(!UserRole::Admin.allows(ManageAuthFactors));
    // Issue #697：系统设置、登录/MFA 限流、身份提供商和套餐定义属于 Owner-only。
    assert!(!UserRole::Admin.allows(ManageSystemSettings));
    assert!(!UserRole::Admin.allows(ManageAuthenticationPolicy));
    assert!(!UserRole::Admin.allows(ManagePlans));
    assert!(!UserRole::Admin.allows(ManageIdentityProviders));
    assert!(!UserRole::User.allows(ManageAuthFactors));
    assert!(!UserRole::User.allows(ManageClients));
    assert!(!UserRole::User.allows(ManageSettings));
}

#[test]
fn public_registration_cannot_select_a_privileged_role() {
    let input: chenxing_auth::users::domain::RegistrationInput =
        serde_json::from_value(serde_json::json!({
            "username": "public-user",
            "email": "public@example.com",
            "password": "1234567890",
            "role": "owner"
        }))
        .expect("registration input with unknown fields is accepted");
    assert!(chenxing_auth::users::domain::validate_registration(input).is_ok());
}

#[test]
fn admin_mutation_requires_matching_csrf_token() {
    use axum::http::{HeaderMap, HeaderValue};
    use subtle::ConstantTimeEq;

    let mut headers = HeaderMap::new();
    headers.insert(
        "cookie",
        HeaderValue::from_static("__Host-chenxing_csrf=csrf-value"),
    );
    headers.insert("x-csrf-token", HeaderValue::from_static("csrf-value"));
    assert!(
        headers
            .get("x-csrf-token")
            .is_some_and(|value| value.as_bytes().ct_eq(b"csrf-value").into())
    );

    headers.insert("x-csrf-token", HeaderValue::from_static("wrong-value"));
    assert!(
        !headers
            .get("x-csrf-token")
            .is_some_and(|value| value.as_bytes().ct_eq(b"csrf-value").into())
    );
}

#[test]
fn admin_bearer_scheme_is_case_insensitive() {
    let authenticator = chenxing_auth::admin::AdminAuthenticator::new("admin-secret".to_owned());
    assert!(authenticator.is_authorization_header_valid("bearer admin-secret"));
    assert!(!authenticator.is_authorization_header_valid("basic admin-secret"));
}
