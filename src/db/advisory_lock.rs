use crate::sqlx::{Postgres, Transaction};
use crate::users::domain::UserId;

/// 固定业务锁使用双 `integer` 键，与单 `bigint` 用户锁属于 PostgreSQL 的独立键空间。
const BUSINESS_LOCK_NAMESPACE: i32 = 0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub(crate) enum BusinessLock {
    OwnerBootstrap = 7_341_928,
    DefaultPlan = 7_341_929,
    /// Serialize passkey policy writes with authentication decisions that read
    /// the policy. A setting row lock is insufficient when the row does not
    /// exist yet, so both sides share this key.
    PasskeyPolicy = 7_341_931,
}

pub(crate) async fn lock_business(
    transaction: &mut Transaction<'_, Postgres>,
    lock: BusinessLock,
) -> Result<(), crate::sqlx::Error> {
    crate::sqlx::query("SELECT pg_advisory_xact_lock($1::integer, $2::integer)")
        .bind(BUSINESS_LOCK_NAMESPACE)
        .bind(lock as i32)
        .execute(&mut **transaction)
        .await?;
    Ok(())
}

/// 保留旧版单 `bigint` 协议，确保滚动升级期间新旧实例仍按用户互斥。
pub(crate) async fn lock_user(
    transaction: &mut Transaction<'_, Postgres>,
    user_id: UserId,
) -> Result<(), crate::sqlx::Error> {
    crate::sqlx::query("SELECT pg_advisory_xact_lock($1::bigint)")
        .bind(user_id)
        .execute(&mut **transaction)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn business_lock_keys_are_stable_and_namespaced() {
        assert_eq!(BUSINESS_LOCK_NAMESPACE, 0);
        assert_eq!(BusinessLock::OwnerBootstrap as i32, 7_341_928);
        assert_eq!(BusinessLock::DefaultPlan as i32, 7_341_929);
        assert_eq!(BusinessLock::PasskeyPolicy as i32, 7_341_931);
    }
}
