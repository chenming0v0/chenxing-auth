use chenxing_auth::admin::domain::{AdminPermission, AdminRole};

#[test]
fn administrator_roles_have_explicit_permissions() {
    assert!(AdminRole::Owner.allows(AdminPermission::ManageUsers));
    assert!(AdminRole::Operator.allows(AdminPermission::ManageClients));
    assert!(!AdminRole::Operator.allows(AdminPermission::RotateKeys));
    assert!(AdminRole::Auditor.allows(AdminPermission::ReadAudit));
    assert!(!AdminRole::Auditor.allows(AdminPermission::ManageUsers));
}

#[test]
fn administrator_roles_round_trip_from_storage_values() {
    assert_eq!(AdminRole::parse("owner"), Some(AdminRole::Owner));
    assert_eq!(AdminRole::parse("operator"), Some(AdminRole::Operator));
    assert_eq!(AdminRole::parse("auditor"), Some(AdminRole::Auditor));
    assert_eq!(AdminRole::parse("root"), None);
    assert_eq!(AdminRole::Auditor.as_str(), "auditor");
}

#[test]
fn administrator_permission_matrix_is_least_privilege() {
    use AdminPermission::*;

    assert!(AdminRole::Owner.allows(ManageUsers));
    assert!(AdminRole::Owner.allows(ManageClients));
    assert!(AdminRole::Owner.allows(RotateKeys));
    assert!(AdminRole::Owner.allows(ReadAudit));
    assert!(AdminRole::Owner.allows(ManageSettings));

    assert!(!AdminRole::Operator.allows(ManageUsers));
    assert!(AdminRole::Operator.allows(ManageClients));
    assert!(!AdminRole::Operator.allows(RotateKeys));
    assert!(!AdminRole::Operator.allows(ManageSettings));
    assert!(!AdminRole::Auditor.allows(ManageClients));
    assert!(!AdminRole::Auditor.allows(ManageSettings));
}

#[test]
fn admin_mutation_requires_matching_csrf_token() {
    use axum::http::{HeaderMap, HeaderValue};
    use chenxing_auth::admin::auth_handlers::admin_csrf_valid;

    let mut headers = HeaderMap::new();
    headers.insert(
        "cookie",
        HeaderValue::from_static("chenxing_admin_csrf=csrf-value"),
    );
    headers.insert("x-csrf-token", HeaderValue::from_static("csrf-value"));
    assert!(admin_csrf_valid(&headers, "csrf-value"));

    headers.insert("x-csrf-token", HeaderValue::from_static("wrong-value"));
    assert!(!admin_csrf_valid(&headers, "csrf-value"));
}

#[test]
fn admin_bearer_scheme_is_case_insensitive() {
    let authenticator = chenxing_auth::admin::AdminAuthenticator::new("admin-secret".to_owned());
    assert!(authenticator.is_authorization_header_valid("bearer admin-secret"));
    assert!(!authenticator.is_authorization_header_valid("basic admin-secret"));
}
