//! Issue #274：`save_authenticated` 在缺少 epoch 校验能力时必须拒绝签发。

use std::time::Duration;

use super::{SessionEpochBinding, SessionStore, SessionStoreError};
use crate::sessions::domain::Session;

fn unreachable_store() -> SessionStore {
    // 用例只验证 Redis I/O **之前**的判定，连接地址故意不可用：
    // 一旦实现改成"先发命令再检查",测试会以 Redis 错误的形式暴露出来。
    SessionStore::with_redis_key(
        redis::Client::open("redis://127.0.0.1:1").expect("unreachable Redis URL"),
        [0x11; 32],
    )
}

/// 纯 Redis 路径读不到 `users.session_epoch`，因此无法确认认证依据是否仍然有效。
///
/// 这种情况必须拒绝签发，而不是把"无法校验"当成"校验通过"降级处理：
/// 后者会让一条本应被拒的凭据在配置退化时静默生效。
#[tokio::test]
async fn authenticated_save_is_refused_without_metadata() {
    let store = unreachable_store();
    let ttl = Duration::from_secs(60);
    let mut session = Session::new_with_idle_timeout("7".to_owned(), ttl, ttl).expect("session");

    let error = store
        .save_authenticated(&mut session, ttl, 0)
        .await
        .expect_err("epoch binding requires metadata");

    assert!(
        matches!(error, SessionStoreError::MetadataUnavailable),
        "expected the metadata requirement to reject the write, got {error}"
    );
}

/// 绑定语义是两类登录来源，不是同一件事的强弱版本：`Current` 不携带任何期望值。
#[test]
fn epoch_binding_distinguishes_current_from_authenticated() {
    assert_ne!(
        SessionEpochBinding::Current,
        SessionEpochBinding::Authenticated(0)
    );
    assert_eq!(
        SessionEpochBinding::Authenticated(3),
        SessionEpochBinding::Authenticated(3)
    );
    assert_ne!(
        SessionEpochBinding::Authenticated(3),
        SessionEpochBinding::Authenticated(4)
    );
}
