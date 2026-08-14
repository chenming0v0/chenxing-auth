use super::{PublicUser, UserRole};

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
