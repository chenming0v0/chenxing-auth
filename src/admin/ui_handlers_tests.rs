//! `admin/ui_handlers` 的单元测试。
//!
//! `session_admin_me_response` 是纯函数，因此「档案缺失」与「数据库故障」这两条
//! 分支不需要真实数据库就能断言——它们在 HTTP 路径上只在竞态窗口里出现
//! （提取器已经查过一次档案），集成测试很难稳定构造（Issue #289）。

use super::*;
use crate::users::repository::UserProfile;
use axum::body::to_bytes;
use axum::http::StatusCode;

fn profile() -> UserProfile {
    UserProfile {
        id: 7,
        username: "owner".to_owned(),
        email: "owner@example.test".to_owned(),
        display_name: None,
        status: "active".to_owned(),
        role: UserRole::Owner,
        avatar_updated_at: None,
    }
}

async fn parts(response: Response) -> (StatusCode, serde_json::Value) {
    let status = response.status();
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body");
    (
        status,
        serde_json::from_slice(&body).expect("response JSON"),
    )
}

#[test]
fn admin_query_times_serialize_as_rfc3339() {
    let value = serde_json::to_value(AdminUserQueryItem {
        id: 1,
        username: "owner".to_owned(),
        email: "owner@example.test".to_owned(),
        display_name: None,
        status: "active".to_owned(),
        role: UserRole::Owner,
        created_at: time::OffsetDateTime::UNIX_EPOCH,
        plan: Some(AdminUserQueryPlan {
            id: 1,
            code: "default".to_owned(),
            name: "Default".to_owned(),
            expires_at: Some(time::OffsetDateTime::UNIX_EPOCH),
        }),
    })
    .expect("admin query item serializes");

    assert_eq!(value["created_at"], "1970-01-01T00:00:00Z");
    assert_eq!(value["plan"]["expires_at"], "1970-01-01T00:00:00Z");
}

#[tokio::test]
async fn admin_me_returns_identity_when_profile_exists() {
    let (status, body) = parts(session_admin_me_response(
        UserRole::Owner,
        Ok(Some(profile())),
    ))
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["user_id"], 7);
    assert_eq!(body["username"], "owner");
    assert_eq!(body["role"], "owner");
}

/// 账号不存在/已删除：会话确实无效，401 是正确答案。
#[tokio::test]
async fn admin_me_returns_unauthorized_when_profile_is_missing() {
    let (status, body) = parts(session_admin_me_response(UserRole::Admin, Ok(None))).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["code"], "invalid_session");
}

/// 数据库故障不得伪装成「会话无效」，否则前端会反复退回登录页。
#[tokio::test]
async fn admin_me_returns_internal_error_when_profile_lookup_fails() {
    let (status, body) = parts(session_admin_me_response(
        UserRole::Owner,
        Err(UserServiceError::Database(crate::sqlx::Error::PoolClosed)),
    ))
    .await;

    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(body["code"], "internal_error");
    // 500 响应体不得泄露数据库细节
    assert_eq!(body["message"], "internal server error");
}

/// 故障与「无此账号」必须给出不同状态码，否则排障时无从区分。
#[test]
fn admin_me_separates_database_failure_from_missing_account() {
    let missing = session_admin_me_response(UserRole::Owner, Ok(None)).status();
    let failed = session_admin_me_response(
        UserRole::Owner,
        Err(UserServiceError::Database(crate::sqlx::Error::PoolClosed)),
    )
    .status();

    assert_ne!(missing, failed);
    assert!(missing.is_client_error());
    assert!(failed.is_server_error());
}

#[test]
fn admin_pagination_rejects_values_outside_the_contract() {
    for query in [
        PageQuery {
            page: Some(0),
            ..Default::default()
        },
        PageQuery {
            page_size: Some(0),
            ..Default::default()
        },
        PageQuery {
            page_size: Some(101),
            ..Default::default()
        },
    ] {
        assert!(bounds(&query).is_none());
    }
}

#[test]
fn admin_pagination_keeps_defaults_when_values_are_omitted() {
    assert_eq!(bounds(&PageQuery::default()), Some((1, 20, 0)));
}

#[test]
fn admin_me_permission_projection_keeps_owner_only_controls_private() {
    let admin = permissions(UserRole::Admin);
    assert!(admin.contains(&"manage_settings"));
    assert!(admin.contains(&"manage_users"));
    for owner_only in [
        "manage_system_settings",
        "manage_authentication_policy",
        "manage_plans",
        "manage_identity_providers",
        "manage_issuer",
        "manage_roles",
        "rotate_keys",
        "manage_auth_factors",
    ] {
        assert!(
            !admin.contains(&owner_only),
            "admin must not receive {owner_only}"
        );
    }
    let owner = permissions(UserRole::Owner);
    for permission in [
        "manage_system_settings",
        "manage_authentication_policy",
        "manage_plans",
        "manage_identity_providers",
    ] {
        assert!(
            owner.contains(&permission),
            "owner must receive {permission}"
        );
    }
}
