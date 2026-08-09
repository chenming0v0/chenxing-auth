//! `ConsentService` 的纯单元测试（Issue #91 分层重构的主要收益）。
//!
//! 拆分前 `ConsentService` 直接持有 `PgPool` 并内嵌 SQL，用例逻辑只能靠
//! 集成测试覆盖；现在存储边界是 `ConsentRepository` trait，这里用内存 mock
//! 验证编排逻辑，**不需要 PostgreSQL 或 Redis**。

use std::sync::{Arc, Mutex};

use chenxing_auth::consents::{
    ConsentService, ConsentServiceError, ConsentState, domain::AuthorizedApp,
    repository::ConsentRepository,
};
use chenxing_auth::users::domain::UserId;
use time::OffsetDateTime;

/// 内存 mock repository：Issue #91 分层重构的主要收益体现。
///
/// 拆分前 `ConsentService` 直接持有 `PgPool` 并内嵌 SQL，service 层用例
/// 只能靠集成测试覆盖；现在可以在不起 PostgreSQL 的情况下验证编排逻辑。
///
/// 内部状态放在 `Arc` 后面，使 mock 可以克隆：测试既能把它交给 service，
/// 也能保留一份句柄继续断言存储侧的最终状态。
#[derive(Clone, Default)]
struct MockConsentRepository {
    state: Arc<MockState>,
}

/// 一条同意记录。
///
/// `state_version` 复现 SQL 侧的 `user_consents.state_version`（Issue #276）：
/// 每次状态跃迁（撤销 / 重新授权）自增，撤销与授权路径把它带进 Redis 条件写。
struct ConsentRecord {
    user_id: UserId,
    client_id: String,
    scopes: Vec<String>,
    revoked: bool,
    state_version: i64,
}

#[derive(Default)]
struct MockState {
    records: Mutex<Vec<ConsentRecord>>,
    /// 已知的 client 集合；不在集合中的 client 会让 upsert 返回 None
    known_clients: Mutex<Vec<String>>,
    /// 强制所有查询返回数据库错误，用于验证错误传播
    fail: bool,
}

impl MockConsentRepository {
    fn with_consent(user_id: UserId, client_id: &str, scopes: &[&str]) -> Self {
        let repository = Self::with_known_client(client_id);
        repository
            .state
            .records
            .lock()
            .expect("records lock")
            .push(ConsentRecord {
                user_id,
                client_id: client_id.to_owned(),
                scopes: scopes.iter().map(|scope| (*scope).to_owned()).collect(),
                revoked: false,
                state_version: 1,
            });
        repository
    }

    fn with_known_clients(client_ids: &[&str]) -> Self {
        Self {
            state: Arc::new(MockState {
                known_clients: Mutex::new(client_ids.iter().map(|id| (*id).to_owned()).collect()),
                ..MockState::default()
            }),
        }
    }

    fn with_known_client(client_id: &str) -> Self {
        Self::with_known_clients(&[client_id])
    }

    fn failing() -> Self {
        Self {
            state: Arc::new(MockState {
                fail: true,
                ..MockState::default()
            }),
        }
    }

    fn revoked_flag(&self, user_id: UserId, client_id: &str) -> Option<bool> {
        self.state
            .records
            .lock()
            .expect("records lock")
            .iter()
            .find(|record| record.user_id == user_id && record.client_id == client_id)
            .map(|record| record.revoked)
    }
}

/// 同步内部实现：所有加锁都收敛在这里。
///
/// trait 方法要求返回的 Future 是 `Send`，而 `std::sync::MutexGuard` 不是 `Send`。
/// 把加锁放进同步辅助函数，async 方法体里就不会出现跨 await 存活的 guard，
/// `Send` 也就不依赖「临时值恰好在同一次 poll 内析构」这种细节。
impl MockConsentRepository {
    fn sync_stored_scopes(&self, user_id: UserId, client_id: &str) -> Option<Vec<String>> {
        self.state
            .records
            .lock()
            .expect("records lock")
            .iter()
            // 已撤销的记录对读路径不可见，与 SQL 的 `revoked_at IS NULL` 一致
            .find(|record| {
                record.user_id == user_id && record.client_id == client_id && !record.revoked
            })
            .map(|record| record.scopes.clone())
    }

    fn sync_upsert(&self, user_id: UserId, client_id: &str, scopes: &[String]) -> Option<i64> {
        let known = self
            .state
            .known_clients
            .lock()
            .expect("clients lock")
            .iter()
            .any(|known| known == client_id);
        if !known {
            // 模拟 `SELECT ... FROM oauth_clients WHERE client_id = $2` 命中 0 行
            return None;
        }
        let mut records = self.state.records.lock().expect("records lock");
        match records
            .iter_mut()
            .find(|record| record.user_id == user_id && record.client_id == client_id)
        {
            Some(record) => {
                record.scopes = scopes.to_vec();
                // 重新授权清除撤销标记，与 SQL 的 `revoked_at = NULL` 一致
                record.revoked = false;
                // 与 SQL 的 `state_version = user_consents.state_version + 1` 一致
                record.state_version += 1;
                Some(record.state_version)
            }
            None => {
                records.push(ConsentRecord {
                    user_id,
                    client_id: client_id.to_owned(),
                    scopes: scopes.to_vec(),
                    revoked: false,
                    state_version: 1,
                });
                Some(1)
            }
        }
    }

    fn sync_list_active(&self, user_id: UserId) -> Vec<AuthorizedApp> {
        self.state
            .records
            .lock()
            .expect("records lock")
            .iter()
            .filter(|record| record.user_id == user_id && !record.revoked)
            .map(|record| AuthorizedApp {
                client_id: record.client_id.clone(),
                client_name: format!("{} name", record.client_id),
                scopes: record.scopes.clone(),
                updated_at: OffsetDateTime::UNIX_EPOCH,
            })
            .collect()
    }

    fn sync_soft_revoke(&self, user_id: UserId, client_id: &str) -> Option<i64> {
        let mut records = self.state.records.lock().expect("records lock");
        let record = records.iter_mut().find(|record| {
            record.user_id == user_id && record.client_id == client_id && !record.revoked
        })?;
        record.revoked = true;
        record.state_version += 1;
        Some(record.state_version)
    }

    fn sync_consent_state(&self, user_id: UserId, client_id: &str) -> Option<ConsentState> {
        self.state
            .records
            .lock()
            .expect("records lock")
            .iter()
            .find(|record| record.user_id == user_id && record.client_id == client_id)
            .map(|record| ConsentState::new(record.revoked, record.state_version))
    }

    fn database_failure(&self) -> Option<chenxing_auth::sqlx::Error> {
        self.state
            .fail
            .then_some(chenxing_auth::sqlx::Error::PoolClosed)
    }
}

impl ConsentRepository for MockConsentRepository {
    async fn stored_scopes(
        &self,
        user_id: UserId,
        client_id: &str,
    ) -> Result<Option<Vec<String>>, chenxing_auth::sqlx::Error> {
        match self.database_failure() {
            Some(error) => Err(error),
            None => Ok(self.sync_stored_scopes(user_id, client_id)),
        }
    }

    async fn upsert_consent(
        &self,
        user_id: UserId,
        client_id: &str,
        scopes: &[String],
    ) -> Result<Option<i64>, chenxing_auth::sqlx::Error> {
        match self.database_failure() {
            Some(error) => Err(error),
            None => Ok(self.sync_upsert(user_id, client_id, scopes)),
        }
    }

    async fn list_active_for_user(
        &self,
        user_id: UserId,
    ) -> Result<Vec<AuthorizedApp>, chenxing_auth::sqlx::Error> {
        match self.database_failure() {
            Some(error) => Err(error),
            None => Ok(self.sync_list_active(user_id)),
        }
    }

    async fn soft_revoke(
        &self,
        user_id: UserId,
        client_id: &str,
    ) -> Result<Option<i64>, chenxing_auth::sqlx::Error> {
        match self.database_failure() {
            Some(error) => Err(error),
            None => Ok(self.sync_soft_revoke(user_id, client_id)),
        }
    }

    async fn consent_state(
        &self,
        user_id: UserId,
        client_id: &str,
    ) -> Result<Option<ConsentState>, chenxing_auth::sqlx::Error> {
        match self.database_failure() {
            Some(error) => Err(error),
            None => Ok(self.sync_consent_state(user_id, client_id)),
        }
    }
}

// ========== Issue #70 回归：client 不存在时的业务信号 ==========

#[tokio::test]
async fn save_reports_client_not_found_when_client_is_unknown() {
    let service = ConsentService::with_repository(MockConsentRepository::default());

    let error = service
        .save(1, "cx_missing", &["openid".to_owned()])
        .await
        .expect_err("unknown client must be rejected");

    assert!(matches!(error, ConsentServiceError::ClientNotFound));
}

#[tokio::test]
async fn save_succeeds_for_known_client() {
    let service =
        ConsentService::with_repository(MockConsentRepository::with_known_client("cx_known"));

    service
        .save(1, "cx_known", &["openid".to_owned()])
        .await
        .expect("known client consent saves");

    assert!(
        service
            .has_scopes(1, "cx_known", &["openid".to_owned()])
            .await
            .expect("scope lookup")
    );
}

#[tokio::test]
async fn save_propagates_database_errors_without_masking_them_as_client_not_found() {
    let service = ConsentService::with_repository(MockConsentRepository::failing());

    let error = service
        .save(1, "cx_known", &["openid".to_owned()])
        .await
        .expect_err("database failure must surface");

    // 基础设施故障不能被误判成 ClientNotFound（否则会把 503 降级成业务错误）
    assert!(matches!(error, ConsentServiceError::Database(_)));
}

// ========== scope 判定 ==========

#[tokio::test]
async fn has_scopes_is_false_without_any_consent_record() {
    let service = ConsentService::with_repository(MockConsentRepository::default());

    assert!(
        !service
            .has_scopes(1, "cx_app", &["openid".to_owned()])
            .await
            .expect("scope lookup")
    );
}

#[tokio::test]
async fn has_scopes_rejects_scopes_beyond_the_granted_set() {
    let service = ConsentService::with_repository(MockConsentRepository::with_consent(
        1,
        "cx_app",
        &["openid", "profile"],
    ));

    assert!(
        service
            .has_scopes(1, "cx_app", &["openid".to_owned(), "profile".to_owned()])
            .await
            .expect("granted scopes")
    );
    assert!(
        !service
            .has_scopes(1, "cx_app", &["openid".to_owned(), "email".to_owned()])
            .await
            .expect("ungranted scope")
    );
}

// ========== Issue #64 / #65：撤销的持久语义 ==========

#[tokio::test]
async fn revoke_marks_consent_revoked_instead_of_deleting_the_record() {
    let repository = MockConsentRepository::with_consent(1, "cx_app", &["openid"]);
    let service = ConsentService::with_repository(repository);

    assert!(
        service
            .revoke_for_user(1, "cx_app")
            .await
            .expect("first revoke")
            .is_some()
    );

    // 撤销事实必须可被权威查询观察到（Redis 缓存未命中时的回源路径）
    assert!(service.is_revoked(1, "cx_app").await.expect("revoked flag"));
}

// ========== Issue #276：状态版本号 ==========

#[tokio::test]
async fn every_state_transition_advances_the_version() {
    let service =
        ConsentService::with_repository(MockConsentRepository::with_known_client("cx_app"));

    let first_grant = service
        .save(1, "cx_app", &["openid".to_owned()])
        .await
        .expect("first grant");
    let revoked = service
        .revoke_for_user(1, "cx_app")
        .await
        .expect("revoke")
        .expect("revoke produces a version");
    let regranted = service
        .save(1, "cx_app", &["openid".to_owned()])
        .await
        .expect("re-authorize");

    // 版本号严格单调：Redis 条件写据此拒绝迟到的撤销写入（Issue #276）
    assert!(revoked > first_grant);
    assert!(regranted > revoked);
    // 版本号与状态同步产生，两者不会错位
    assert_eq!(
        service
            .consent_state(1, "cx_app")
            .await
            .expect("state")
            .expect("record exists"),
        ConsentState::new(false, regranted)
    );
}

#[tokio::test]
async fn idempotent_revoke_does_not_consume_a_version() {
    let service = ConsentService::with_repository(MockConsentRepository::with_consent(
        1,
        "cx_app",
        &["openid"],
    ));
    let revoked = service
        .revoke_for_user(1, "cx_app")
        .await
        .expect("first revoke")
        .expect("first revoke produces a version");

    // 第二次没有生效授权可撤销，因此不产生新版本；否则重复的撤销请求会白白
    // 抬高版本号，让一个本来合法的重新授权写入被围栏挡住。
    assert_eq!(
        service.revoke_for_user(1, "cx_app").await.expect("second"),
        None
    );
    assert_eq!(
        service
            .consent_state(1, "cx_app")
            .await
            .expect("state")
            .expect("record exists"),
        ConsentState::new(true, revoked)
    );
}

#[tokio::test]
async fn consent_state_is_absent_for_a_consent_that_never_existed() {
    let service = ConsentService::with_repository(MockConsentRepository::default());

    // 没有记录就没有版本号可比较；缓存路径据此跳过回填
    assert_eq!(
        service
            .consent_state(1, "cx_unknown")
            .await
            .expect("missing consent"),
        None
    );
}

#[tokio::test]
async fn revoked_app_disappears_from_the_authorized_list() {
    let service = ConsentService::with_repository(MockConsentRepository::with_consent(
        1,
        "cx_app",
        &["openid"],
    ));
    assert_eq!(
        service.list_for_user(1).await.expect("initial list").len(),
        1
    );

    service
        .revoke_for_user(1, "cx_app")
        .await
        .expect("revoke consent");

    // 软删除后不再展示：撤销证据留在库中，但列表只含生效授权
    assert!(service.list_for_user(1).await.expect("list").is_empty());
    // 同时 scope 判定也必须失效，否则 refresh token 仍能通过 has_scopes
    assert!(
        !service
            .has_scopes(1, "cx_app", &["openid".to_owned()])
            .await
            .expect("scope after revoke")
    );
}

#[tokio::test]
async fn revoking_twice_is_idempotent() {
    let service = ConsentService::with_repository(MockConsentRepository::with_consent(
        1,
        "cx_app",
        &["openid"],
    ));

    assert!(
        service
            .revoke_for_user(1, "cx_app")
            .await
            .expect("first revoke")
            .is_some()
    );
    // 第二次没有生效授权可撤销：返回 None，handler 幂等返回 204
    assert!(
        service
            .revoke_for_user(1, "cx_app")
            .await
            .expect("second revoke")
            .is_none()
    );
}

#[tokio::test]
async fn revoking_an_unknown_consent_reports_no_change() {
    let service = ConsentService::with_repository(MockConsentRepository::default());

    assert!(
        service
            .revoke_for_user(1, "cx_never_authorized")
            .await
            .expect("revoke missing consent")
            .is_none()
    );
}

#[tokio::test]
async fn re_authorizing_clears_the_persisted_revocation() {
    let repository = MockConsentRepository::with_consent(1, "cx_app", &["openid"]);
    let service = ConsentService::with_repository(repository);
    service
        .revoke_for_user(1, "cx_app")
        .await
        .expect("revoke consent");
    assert!(service.is_revoked(1, "cx_app").await.expect("revoked"));

    // 重新授权必须清除持久化的撤销标记，否则回源查询会永久拒绝该用户
    service
        .save(1, "cx_app", &["openid".to_owned()])
        .await
        .expect("re-authorize");

    assert!(
        !service
            .is_revoked(1, "cx_app")
            .await
            .expect("revocation cleared")
    );
    assert!(
        service
            .has_scopes(1, "cx_app", &["openid".to_owned()])
            .await
            .expect("scopes restored")
    );
}

#[tokio::test]
async fn revocation_is_scoped_to_one_user_and_client_pair() {
    let service = ConsentService::with_repository(MockConsentRepository::with_known_clients(&[
        "cx_a", "cx_b",
    ]));
    service
        .save(1, "cx_a", &["openid".to_owned()])
        .await
        .expect("user 1 client a");
    service
        .save(1, "cx_b", &["openid".to_owned()])
        .await
        .expect("user 1 client b");
    service
        .save(2, "cx_a", &["openid".to_owned()])
        .await
        .expect("user 2 client a");

    service
        .revoke_for_user(1, "cx_a")
        .await
        .expect("revoke one pair");

    assert!(service.is_revoked(1, "cx_a").await.expect("target revoked"));
    assert!(
        !service
            .is_revoked(1, "cx_b")
            .await
            .expect("other client intact")
    );
    assert!(
        !service
            .is_revoked(2, "cx_a")
            .await
            .expect("other user intact")
    );
}

#[tokio::test]
async fn is_revoked_is_false_for_a_consent_that_never_existed() {
    let service = ConsentService::with_repository(MockConsentRepository::default());

    // 不存在的授权无法被撤销；拦截由 has_scopes 负责，不是 is_revoked
    assert!(
        !service
            .is_revoked(1, "cx_unknown")
            .await
            .expect("missing consent")
    );
}

#[tokio::test]
async fn revoke_propagates_database_errors() {
    let service = ConsentService::with_repository(MockConsentRepository::failing());

    assert!(service.revoke_for_user(1, "cx_app").await.is_err());
    assert!(service.is_revoked(1, "cx_app").await.is_err());
}

#[tokio::test]
async fn revoked_record_is_kept_as_audit_evidence_instead_of_being_deleted() {
    // mock 可克隆，因此测试保留一份句柄观察存储侧的最终状态
    let repository = MockConsentRepository::with_consent(1, "cx_app", &["openid"]);
    let service = ConsentService::with_repository(repository.clone());

    service
        .revoke_for_user(1, "cx_app")
        .await
        .expect("revoke consent");

    // 行仍然存在，只是 revoked 标记为 true —— 这正是 #64 要求的「保留撤销证据」，
    // 而不是拆分前 `DELETE FROM user_consents` 那种「删掉行就没了证据」。
    assert_eq!(repository.revoked_flag(1, "cx_app"), Some(true));
}
