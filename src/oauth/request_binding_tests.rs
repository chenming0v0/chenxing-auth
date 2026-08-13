//! [`super::bind_pending_request`] 的存储级测试。
//!
//! 覆盖 #115（holder 必须匹配）与 #270（受控重绑与幂等）。需要 Redis。

use super::{PendingRequestBinding, PendingRequestBindingError, bind_pending_request};
use crate::oauth::{consent::PendingAuthorization, request_store::AuthorizationRequestStore};
use crate::sessions::{cookies, domain::session_token_hash};

const HOLDER: &str = "test-holder";

fn store() -> AuthorizationRequestStore {
    let url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
    AuthorizationRequestStore::new(redis::Client::open(url).expect("Redis URL"))
}

fn holder_hash() -> String {
    cookies::authz_holder_hash(HOLDER)
}

fn pending(label: &str) -> PendingAuthorization {
    let unique = uuid::Uuid::new_v4().simple().to_string();
    PendingAuthorization {
        request_id: format!("{label}-{unique}"),
        client_id: format!("{label}-client-{unique}"),
        redirect_uri: "https://client.example/callback".to_owned(),
        scope: "openid".to_owned(),
        state: "state".to_owned(),
        nonce: None,
        code_challenge: "challenge".to_owned(),
        code_challenge_method: "S256".to_owned(),
        session_token_hash: None,
        holder_hash: Some(holder_hash()),
    }
}

async fn stored_session_hash(
    store: &AuthorizationRequestStore,
    request_id: &str,
) -> Option<String> {
    store
        .find(request_id)
        .await
        .expect("find pending request")
        .expect("pending request exists")
        .session_token_hash
}

/// #270：会话过期后浏览器换新会话，同一 holder 必须能把请求重绑过去。
/// 旧行为在这里恒定返回 invalid_session，前端跟着反复跳登录页。
#[tokio::test]
async fn expired_session_can_rebind_pending_request_with_same_holder() {
    let store = store();
    let mut request = pending("rebind-after-expiry");
    request.session_token_hash = Some(session_token_hash("expired-session"));
    store.save(&request).await.expect("save pending request");

    assert_eq!(
        bind_pending_request(
            &store,
            &request.request_id,
            "fresh-session",
            Some(holder_hash().as_str()),
        )
        .await,
        Ok(PendingRequestBinding::Rebound)
    );
    assert_eq!(
        stored_session_hash(&store, &request.request_id).await,
        Some(session_token_hash("fresh-session")),
        "pending request must now be held by the fresh session"
    );

    store
        .take(&request.request_id)
        .await
        .expect("cleanup pending request");
}

/// #270：同一浏览器切换账号（登出后换账号登录）同样是重绑，不是攻击。
/// 重绑后的会话摘要决定授权码归属，因此必须指向新账号的会话。
#[tokio::test]
async fn account_switch_rebinds_pending_request_to_the_new_session() {
    let store = store();
    let mut request = pending("rebind-account-switch");
    request.session_token_hash = Some(session_token_hash("first-account-session"));
    store.save(&request).await.expect("save pending request");

    assert_eq!(
        bind_pending_request(
            &store,
            &request.request_id,
            "second-account-session",
            Some(holder_hash().as_str()),
        )
        .await,
        Ok(PendingRequestBinding::Rebound)
    );
    assert_eq!(
        stored_session_hash(&store, &request.request_id).await,
        Some(session_token_hash("second-account-session"))
    );

    // 再切回第一个账号仍然允许：重绑是幂等可逆的状态更新，不是一次性动作。
    assert_eq!(
        bind_pending_request(
            &store,
            &request.request_id,
            "first-account-session",
            Some(holder_hash().as_str()),
        )
        .await,
        Ok(PendingRequestBinding::Rebound)
    );
    assert_eq!(
        stored_session_hash(&store, &request.request_id).await,
        Some(session_token_hash("first-account-session"))
    );

    store
        .take(&request.request_id)
        .await
        .expect("cleanup pending request");
}

/// 首次绑定与同会话重试：后者必须是幂等的 `Unchanged`，且不改动载荷。
#[tokio::test]
async fn first_bind_then_same_session_retry_is_idempotent() {
    let store = store();
    let request = pending("bind-idempotent");
    store.save(&request).await.expect("save pending request");

    assert_eq!(
        bind_pending_request(
            &store,
            &request.request_id,
            "session-a",
            Some(holder_hash().as_str()),
        )
        .await,
        Ok(PendingRequestBinding::Bound)
    );
    assert_eq!(
        bind_pending_request(
            &store,
            &request.request_id,
            "session-a",
            Some(holder_hash().as_str()),
        )
        .await,
        Ok(PendingRequestBinding::Unchanged)
    );
    assert_eq!(
        stored_session_hash(&store, &request.request_id).await,
        Some(session_token_hash("session-a"))
    );

    store
        .take(&request.request_id)
        .await
        .expect("cleanup pending request");
}

/// 并发绑定必须收敛：CAS 保证最终只有一个会话摘要落盘，且两个调用都不报错。
///
/// 重绑语义下并发的输赢不再体现为「一个成功一个失败」，而是「都成功、最后
/// 写入者胜出」——这是正确的，因为两个请求都通过了 holder 与会话校验。
#[tokio::test]
async fn concurrent_binds_converge_to_a_single_session_hash() {
    let store = store();
    let request = pending("bind-concurrent");
    store.save(&request).await.expect("save pending request");

    let first_store = store.clone();
    let second_store = store.clone();
    let holder = holder_hash();
    let (first, second) = tokio::join!(
        bind_pending_request(
            &first_store,
            &request.request_id,
            "session-a",
            Some(holder.as_str()),
        ),
        bind_pending_request(
            &second_store,
            &request.request_id,
            "session-b",
            Some(holder.as_str()),
        ),
    );
    assert!(first.is_ok(), "concurrent bind must not fail: {first:?}");
    assert!(second.is_ok(), "concurrent bind must not fail: {second:?}");

    let bound = stored_session_hash(&store, &request.request_id)
        .await
        .expect("bound session hash");
    assert!(
        bound == session_token_hash("session-a") || bound == session_token_hash("session-b"),
        "stored hash must be exactly one of the competing sessions"
    );

    store
        .take(&request.request_id)
        .await
        .expect("cleanup pending request");
}

/// #115：没有 holder Cookie 一律拒绝，且不得改动已有绑定。
#[tokio::test]
async fn binding_without_holder_cookie_is_rejected_and_leaves_binding_intact() {
    let store = store();
    let mut request = pending("bind-no-holder");
    request.session_token_hash = Some(session_token_hash("session-a"));
    store.save(&request).await.expect("save pending request");

    assert_eq!(
        bind_pending_request(&store, &request.request_id, "session-b", None).await,
        Err(PendingRequestBindingError::HolderInvalid)
    );
    assert_eq!(
        stored_session_hash(&store, &request.request_id).await,
        Some(session_token_hash("session-a")),
        "rejected bind must not touch the existing binding"
    );

    store
        .take(&request.request_id)
        .await
        .expect("cleanup pending request");
}

/// #115 + #270：holder 不匹配的第三方即使持有有效会话也不能重绑。
/// 这是重绑语义安全性的核心断言——放开会话检查后，holder 是唯一的所有权门。
#[tokio::test]
async fn mismatched_holder_cannot_rebind_another_browsers_request() {
    let store = store();
    let mut request = pending("bind-mismatched-holder");
    request.session_token_hash = Some(session_token_hash("victim-session"));
    store.save(&request).await.expect("save pending request");
    let attacker_holder = cookies::authz_holder_hash("attacker-holder");

    assert_eq!(
        bind_pending_request(
            &store,
            &request.request_id,
            "attacker-session",
            Some(attacker_holder.as_str()),
        )
        .await,
        Err(PendingRequestBindingError::HolderInvalid)
    );
    assert_eq!(
        stored_session_hash(&store, &request.request_id).await,
        Some(session_token_hash("victim-session"))
    );

    store
        .take(&request.request_id)
        .await
        .expect("cleanup pending request");
}

/// 升级前创建的旧记录没有 holder 摘要：fail-secure，拒绝绑定。
#[tokio::test]
async fn legacy_pending_request_without_holder_hash_is_rejected() {
    let store = store();
    let mut request = pending("bind-legacy");
    request.holder_hash = None;
    store.save(&request).await.expect("save pending request");

    assert_eq!(
        bind_pending_request(
            &store,
            &request.request_id,
            "session-a",
            Some(holder_hash().as_str()),
        )
        .await,
        Err(PendingRequestBindingError::HolderInvalid)
    );

    store
        .take(&request.request_id)
        .await
        .expect("cleanup pending request");
}

/// 已被消费或已过期的请求按 `Expired` 处理，不得静默创建新记录。
#[tokio::test]
async fn missing_pending_request_is_expired() {
    let store = store();
    let request_id = format!("bind-missing-{}", uuid::Uuid::new_v4().simple());

    assert_eq!(
        bind_pending_request(
            &store,
            &request_id,
            "session-a",
            Some(holder_hash().as_str()),
        )
        .await,
        Err(PendingRequestBindingError::Expired)
    );
    assert!(
        store
            .find(&request_id)
            .await
            .expect("find missing request")
            .is_none(),
        "a failed bind must not materialize a pending request"
    );
}
