use super::{PublicUser, UserRole, UserStatus};

#[test]
fn public_user_serializes_creation_time_as_rfc3339() {
    let value = serde_json::to_value(PublicUser {
        id: 1,
        username: "owner".to_owned(),
        email: "owner@example.test".to_owned(),
        display_name: None,
        status: "active".to_owned(),
        role: UserRole::Owner,
        created_at: time::OffsetDateTime::UNIX_EPOCH,
    })
    .expect("public user serializes");

    assert_eq!(value["created_at"], "1970-01-01T00:00:00Z");
}

/// Issue #646: a disabled Owner row must not authenticate as Owner.
#[test]
fn authenticated_row_rejects_non_active_status_even_for_owner() {
    assert_eq!(UserRole::from_authenticated_row("owner", "disabled"), None);
    assert_eq!(UserRole::from_authenticated_row("admin", "disabled"), None);
    assert_eq!(UserRole::from_authenticated_row("owner", "bogus"), None);
}

#[test]
fn authenticated_row_binds_active_role_and_degrades_unknown_roles() {
    assert_eq!(
        UserRole::from_authenticated_row("owner", "active"),
        Some((UserRole::Owner, UserStatus::Active))
    );
    assert_eq!(
        UserRole::from_authenticated_row("admin", "active"),
        Some((UserRole::Admin, UserStatus::Active))
    );
    assert_eq!(
        UserRole::from_authenticated_row("not-a-role", "active"),
        Some((UserRole::User, UserStatus::Active))
    );
}
